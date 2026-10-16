import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    CloudAccountConnection,
    CloudAsset,
    CloudPrivEscPath,
    Engagement,
    Finding,
    HostConnection,
    OAuthAppConnection,
    OAuthGrant,
)
from app.services import graph_service
from app.services.attack_technique_mapping import (
    attack_techniques_for_actions,
    attack_techniques_for_can_access,
    attack_techniques_for_internet_exposure,
    attack_techniques_for_lateral_movement,
    attack_techniques_for_runs_as,
)
from app.services.identity_resolution_service import resolve_or_create_actor
from app.services.privesc_remediation_mapping import remediation_for_edge
from tests.factories import make_tenant


def test_remediation_for_edge_uses_escalation_type_when_present():
    text = remediation_for_edge("PassExistingRoleToNewLambdaThenInvoke", ["iam:PassRole", "lambda:CreateFunction"])
    assert "lambda" in text.lower()
    assert "passrole" in text.lower()


def test_remediation_for_edge_falls_back_to_first_action_when_no_escalation_type():
    text = remediation_for_edge(None, ["iam:CreateAccessKey"])
    assert "createaccesskey" in text.lower()


def test_remediation_for_edge_handles_oauth_scopes():
    text = remediation_for_edge(None, ["Mail.Send"])
    assert "spearphishing" in text.lower()


def test_remediation_for_edge_has_a_real_default_for_unknown_actions():
    text = remediation_for_edge(None, ["some:UnknownAction"])
    assert text  # never empty
    assert "unknownaction" not in text.lower()  # a real generic sentence, not an echo of the raw action


def test_remediation_for_edge_has_a_real_default_for_empty_chain():
    text = remediation_for_edge(None, [])
    assert text


def test_attack_techniques_for_actions_maps_known_iam_actions():
    techniques = attack_techniques_for_actions(["iam:PassRole"])
    assert techniques[0]["id"] == "T1548.005"


def test_attack_techniques_for_actions_falls_back_for_unknown_actions():
    techniques = attack_techniques_for_actions(["some:UnknownAction"])
    assert len(techniques) == 1
    assert techniques[0]["id"] == "T1078.004"  # the default


def test_attack_techniques_for_actions_dedupes_repeated_technique_ids():
    # iam:AttachUserPolicy and iam:PutRolePolicy both map to the same technique
    techniques = attack_techniques_for_actions(["iam:AttachUserPolicy", "iam:PutRolePolicy"])
    assert len(techniques) == 1


def test_attack_techniques_for_runs_as_returns_a_real_fixed_technique():
    techniques = attack_techniques_for_runs_as()
    assert techniques == [{"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts", "tactics": ["Privilege Escalation"]}]


def test_attack_techniques_for_internet_exposure_returns_a_real_fixed_technique():
    techniques = attack_techniques_for_internet_exposure()
    assert techniques == [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactics": ["Initial Access"]}]


def test_friendly_label_parses_iam_role_arn():
    label, hue = graph_service._friendly_label("arn:aws:iam::123456789012:role/ec2-deploy-role")
    assert label == "role/ec2-deploy-role"
    assert hue == "amber"


def test_friendly_label_falls_back_for_non_iam_arn():
    label, hue = graph_service._friendly_label("account-admin")
    assert label == "account-admin"
    assert hue == "cyan"


async def _make_connection_and_engagement(db_session: AsyncSession, tenant):
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123",
        status="connected",
    )
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add_all([connection, engagement])
    await db_session.flush()
    return connection, engagement


async def test_build_tenant_privesc_graph_returns_empty_for_a_tenant_with_no_paths(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert graph["nodes"] == []
    assert graph["edges"] == []
    assert graph["last_analyzed"] is None
    assert graph["sources"] == []


async def test_build_tenant_privesc_graph_assembles_nodes_and_edges(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/ec2-deploy-role",
        target_principal_arn="account-admin",
        technique_chain=["iam:PassRole", "iam:CreatePolicyVersion"],
        severity="critical",
    )
    db_session.add(path)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)

    assert len(graph["nodes"]) == 2
    node_ids = {n["id"] for n in graph["nodes"]}
    assert node_ids == {"arn:aws:iam::123456789012:role/ec2-deploy-role", "account-admin"}

    assert len(graph["edges"]) == 1
    edge = graph["edges"][0]
    assert edge["source"] == "arn:aws:iam::123456789012:role/ec2-deploy-role"
    assert edge["target"] == "account-admin"
    assert edge["severity"] == "critical"
    assert len(edge["attack_techniques"]) == 2  # PassRole and CreatePolicyVersion map to different techniques
    assert edge["remediation"] == remediation_for_edge(None, ["iam:PassRole", "iam:CreatePolicyVersion"])

    assert graph["last_analyzed"] is not None
    assert graph["sources"] == ["IAM Privilege-Escalation Graph (Cloudsplaining)"]


async def test_compute_fix_verifications_reports_fully_closed_policy(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    from datetime import datetime, timezone
    closed_at = datetime.now(timezone.utc)
    policy = "arn:aws:iam::123456789012:policy/leaky"
    p1 = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/a", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical", policy_arn=policy, policy_name="leaky",
        status="retest_closed", closed_at=closed_at,
    )
    p2 = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/b", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical", policy_arn=policy, policy_name="leaky",
        status="retest_closed", closed_at=closed_at,
    )
    db_session.add_all([p1, p2])
    await db_session.commit()

    verifications = await graph_service.get_fix_verifications(db_session, tenant.id)
    assert len(verifications) == 1
    v = verifications[0]
    assert v["closed_count"] == 2
    assert v["still_open_count"] == 0
    assert v["fully_closed"] is True
    assert v["latest_closed_at"] is not None


async def test_compute_fix_verifications_reports_partial_closure_honestly(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    policy = "arn:aws:iam::123456789012:policy/leaky"
    closed = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/a", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical", policy_arn=policy, policy_name="leaky",
        status="retest_closed",
    )
    still_open = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/b", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical", policy_arn=policy, policy_name="leaky",
        status="open",
    )
    db_session.add_all([closed, still_open])
    await db_session.commit()

    verifications = await graph_service.get_fix_verifications(db_session, tenant.id)
    assert len(verifications) == 1
    v = verifications[0]
    assert v["closed_count"] == 1
    assert v["still_open_count"] == 1
    assert v["fully_closed"] is False  # never falsely green when a sibling path is still open


async def test_compute_fix_verifications_excludes_policies_with_nothing_closed(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/a", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical", policy_arn="arn:aws:iam::123456789012:policy/still-open",
        status="open",
    )
    db_session.add(path)
    await db_session.commit()

    verifications = await graph_service.get_fix_verifications(db_session, tenant.id)
    assert verifications == []


async def test_build_tenant_privesc_graph_is_scoped_to_tenant(db_session: AsyncSession):
    tenant_a = await make_tenant(db_session, name="Tenant A")
    tenant_b = await make_tenant(db_session, name="Tenant B")
    connection, engagement = await _make_connection_and_engagement(db_session, tenant_a)

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant_a.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/only-tenant-a",
        target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high",
    )
    db_session.add(path)
    await db_session.commit()

    graph_a = await graph_service.build_tenant_privesc_graph(db_session, tenant_a.id)
    graph_b = await graph_service.build_tenant_privesc_graph(db_session, tenant_b.id)

    assert len(graph_a["nodes"]) == 2
    assert graph_b["nodes"] == []


async def _make_oauth_engagement_and_connection(db_session: AsyncSession, tenant):
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="oauth_risk", status="active")
    db_session.add(engagement)
    await db_session.flush()
    connection = OAuthAppConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, provider="microsoft365",
        status="connected",
    )
    db_session.add(connection)
    await db_session.flush()
    return engagement, connection


async def test_build_tenant_privesc_graph_includes_oauth_grants(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    engagement, connection = await _make_oauth_engagement_and_connection(db_session, tenant)
    await resolve_or_create_actor(db_session, tenant.id, "microsoft365", "jane@example.com", email="jane@example.com")

    grant = OAuthGrant(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, connection_id=connection.id,
        grantee_principal="jane@example.com", app_name="Zapier", app_client_id="app-guid-1",
        scopes=["Mail.ReadWrite"], risk_tier="high",
    )
    db_session.add(grant)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert len(graph["nodes"]) == 2
    app_node = next(n for n in graph["nodes"] if n["kind"] == "third_party_app")
    assert app_node["id"] == "app:app-guid-1"
    assert app_node["label"] == "Zapier"

    person_node = next(n for n in graph["nodes"] if n["kind"] == "principal")
    assert person_node["id"] == "jane@example.com"  # no matching aws_iam identity — falls back to the raw email

    assert len(graph["edges"]) == 1
    edge = graph["edges"][0]
    assert edge["source"] == "jane@example.com"
    assert edge["target"] == "app:app-guid-1"
    assert edge["severity"] == "high"
    assert graph["sources"] == ["Third-Party OAuth App Risk (Microsoft 365)"]


async def test_build_tenant_privesc_graph_merges_oauth_grantee_with_existing_iam_node(db_session: AsyncSession):
    """The actual payoff (OAUTH_APP_RISK_DESIGN.md Section 6): when the same
    Actor is known via both an AWS IAM ARN and a Microsoft 365 email, the
    OAuth edge attaches to the *same* node as that person's IAM
    privilege-escalation path — one human, one node, not two."""
    tenant = await make_tenant(db_session)
    cloud_connection, cloud_engagement = await _make_connection_and_engagement(db_session, tenant)
    oauth_engagement, oauth_connection = await _make_oauth_engagement_and_connection(db_session, tenant)

    iam_arn = "arn:aws:iam::123456789012:role/ec2-deploy-role"
    await resolve_or_create_actor(db_session, tenant.id, "aws_iam", iam_arn, email="jane@example.com")
    await resolve_or_create_actor(db_session, tenant.id, "microsoft365", "jane@example.com", email="jane@example.com")

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=cloud_engagement.id,
        cloud_account_connection_id=cloud_connection.id,
        source_principal_arn=iam_arn, target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical",
    )
    grant = OAuthGrant(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=oauth_engagement.id, connection_id=oauth_connection.id,
        grantee_principal="jane@example.com", app_name="Zapier", app_client_id="app-guid-1",
        scopes=["Mail.ReadWrite"], risk_tier="high",
    )
    db_session.add_all([path, grant])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)

    # 3 nodes, not 4: the IAM role, "account-admin", and the app — jane's
    # OAuth grant attaches to the IAM role node instead of a 4th node keyed
    # by her email.
    assert len(graph["nodes"]) == 3
    node_ids = {n["id"] for n in graph["nodes"]}
    assert node_ids == {iam_arn, "account-admin", "app:app-guid-1"}

    oauth_edge = next(e for e in graph["edges"] if e["target"] == "app:app-guid-1")
    assert oauth_edge["source"] == iam_arn
    assert len(graph["sources"]) == 2


# ── Phase 36f: a narrow, honest graph cross-link — a node badge counting
# open tier='credential' findings that ARN-match that exact node, nothing
# more (the graph's own edges stay privesc/OAuth-only). ──

async def test_build_tenant_privesc_graph_counts_open_credential_findings_on_a_matching_node(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    arn = "arn:aws:iam::123456789012:role/ec2-deploy-role"

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn=arn, target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical",
    )
    open_finding_1 = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="credential", severity="high", title="no MFA", status="open",
        check_id="credential_report_mfa_missing", resource_uid=arn,
    )
    open_finding_2 = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="credential", severity="medium", title="stale key", status="open",
        check_id="credential_report_access_key_1_stale", resource_uid=arn,
    )
    # Remediated — must not count.
    remediated_finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="credential", severity="high", title="old, fixed", status="remediated",
        check_id="credential_report_password_stale", resource_uid=arn,
    )
    # A different tier on the same ARN — out of scope for this badge, must not count.
    cloud_finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="cloud", severity="high", title="unrelated Prowler finding", status="open",
        check_id="iam_root_mfa_enabled", resource_uid=arn,
    )
    db_session.add_all([path, open_finding_1, open_finding_2, remediated_finding, cloud_finding])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)

    node = next(n for n in graph["nodes"] if n["id"] == arn)
    assert node["open_credential_findings"] == 2
    # "account-admin" isn't a real ARN — never ARN-matchable, stays 0.
    admin_node = next(n for n in graph["nodes"] if n["id"] == "account-admin")
    assert admin_node["open_credential_findings"] == 0


async def test_build_tenant_privesc_graph_defaults_open_credential_findings_to_zero(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/clean-role",
        target_principal_arn="account-admin", technique_chain=["iam:PassRole"], severity="high",
    )
    db_session.add(path)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert all(n["open_credential_findings"] == 0 for n in graph["nodes"])


async def test_build_tenant_privesc_graph_credential_finding_count_is_tenant_scoped(db_session: AsyncSession):
    tenant_a = await make_tenant(db_session, name="Tenant A")
    tenant_b = await make_tenant(db_session, name="Tenant B")
    connection_a, engagement_a = await _make_connection_and_engagement(db_session, tenant_a)
    _connection_b, engagement_b = await _make_connection_and_engagement(db_session, tenant_b)
    arn = "arn:aws:iam::123456789012:role/shared-looking-name"

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant_a.id, engagement_id=engagement_a.id,
        cloud_account_connection_id=connection_a.id,
        source_principal_arn=arn, target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high",
    )
    # Same ARN string, but tenant B's own finding — must never bleed into tenant A's graph.
    other_tenant_finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant_b.id, engagement_id=engagement_b.id,
        tier="credential", severity="high", title="belongs to tenant B", status="open",
        check_id="credential_report_mfa_missing", resource_uid=arn,
    )
    db_session.add_all([path, other_tenant_finding])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant_a.id)
    node = next(n for n in graph["nodes"] if n["id"] == arn)
    assert node["open_credential_findings"] == 0


# ── Phase 37: the same node badge, now resolved through Actor/ActorIdentity
# rather than raw ARN string equality — proving the upgrade actually engages
# end-to-end, not just at the unit level. ──

async def test_build_tenant_privesc_graph_counts_a_finding_that_only_matches_via_an_actor_merge(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    arn = "arn:aws:iam::123456789012:role/ec2-deploy-role"
    # Simulates a future non-AWS credential source (e.g. Azure AD) already
    # merged onto the same human via email — 36f's raw string-equality
    # design could never have matched this; the Actor-based version does.
    other_provider_id = "azure-ad:same-human-object-id"

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn=arn, target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical",
    )
    await resolve_or_create_actor(db_session, tenant.id, "aws_iam", arn, email="jane@example.com")
    await resolve_or_create_actor(db_session, tenant.id, "test_other_provider", other_provider_id, email="jane@example.com")
    other_provider_finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="credential", severity="high", title="stale credential on another provider", status="open",
        check_id="other_provider_stale_credential", resource_uid=other_provider_id,
    )
    db_session.add_all([path, other_provider_finding])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    node = next(n for n in graph["nodes"] if n["id"] == arn)
    assert node["open_credential_findings"] == 1


# ── Catastrophic-capability badge: the subset of open_credential_findings
# that's Cloudsplaining's DataExfiltration/ResourceExposure/ServiceWildcard/
# CredentialsExposure categories, surfaced as its own count + worst severity
# so it isn't indistinguishable from routine password/MFA/key hygiene. ──

async def test_build_tenant_privesc_graph_distinguishes_policy_risk_from_hygiene_findings(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    arn = "arn:aws:iam::123456789012:role/ec2-deploy-role"

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn=arn, target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical",
    )
    policy_risk_finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="credential", severity="critical", title="can exfiltrate S3 data", status="open",
        check_id="cloudsplaining_data_exfiltration", resource_uid=arn,
    )
    hygiene_finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="credential", severity="high", title="no MFA", status="open",
        check_id="credential_report_mfa_missing", resource_uid=arn,
    )
    db_session.add_all([path, policy_risk_finding, hygiene_finding])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    node = next(n for n in graph["nodes"] if n["id"] == arn)
    # The existing blended count is unchanged — proves this is additive.
    assert node["open_credential_findings"] == 2
    # Only the cloudsplaining_* finding counts toward the new, narrower signal.
    assert node["open_policy_risk_findings"] == 1
    assert node["policy_risk_worst_severity"] == "critical"


async def test_build_tenant_privesc_graph_policy_risk_worst_severity_picks_the_real_worst(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    arn = "arn:aws:iam::123456789012:role/ec2-deploy-role"

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn=arn, target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high",
    )
    high_finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="credential", severity="high", title="unconstrained service access", status="open",
        check_id="cloudsplaining_service_wildcard", resource_uid=arn,
    )
    critical_finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="credential", severity="critical", title="can mint new credentials", status="open",
        check_id="cloudsplaining_credentials_exposure", resource_uid=arn,
    )
    db_session.add_all([path, high_finding, critical_finding])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    node = next(n for n in graph["nodes"] if n["id"] == arn)
    assert node["open_policy_risk_findings"] == 2
    assert node["policy_risk_worst_severity"] == "critical"


async def test_build_tenant_privesc_graph_defaults_policy_risk_fields_to_zero_and_none(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    arn = "arn:aws:iam::123456789012:role/ec2-deploy-role"

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn=arn, target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high",
    )
    db_session.add(path)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    node = next(n for n in graph["nodes"] if n["id"] == arn)
    assert node["open_policy_risk_findings"] == 0
    assert node["policy_risk_worst_severity"] is None


async def test_build_tenant_privesc_graph_policy_risk_counted_via_actor_merge(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    arn = "arn:aws:iam::123456789012:role/ec2-deploy-role"
    other_provider_id = "azure-ad:same-human-object-id"

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn=arn, target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical",
    )
    await resolve_or_create_actor(db_session, tenant.id, "aws_iam", arn, email="jane@example.com")
    await resolve_or_create_actor(db_session, tenant.id, "test_other_provider", other_provider_id, email="jane@example.com")
    other_provider_finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="credential", severity="medium", title="data exfil risk on another provider", status="open",
        check_id="cloudsplaining_data_exfiltration", resource_uid=other_provider_id,
    )
    db_session.add_all([path, other_provider_finding])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    node = next(n for n in graph["nodes"] if n["id"] == arn)
    assert node["open_policy_risk_findings"] == 1
    assert node["policy_risk_worst_severity"] == "medium"


# ── Phase 39a: crown-jewel targets, chokepoint ranking, severed edges ──────

async def test_build_tenant_privesc_graph_includes_retest_closed_edges_as_severed(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    closed_path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/fixed-already",
        target_principal_arn="account-admin", technique_chain=["iam:PassRole"],
        severity="high", status="retest_closed",
    )
    db_session.add(closed_path)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert len(graph["edges"]) == 1
    assert graph["edges"][0]["status"] == "retest_closed"
    # The node itself still appears — a severed path is real history, not erased.
    assert any(n["id"] == "arn:aws:iam::123456789012:role/fixed-already" for n in graph["nodes"])


async def test_build_tenant_privesc_graph_open_edges_default_to_open_status(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/still-open",
        target_principal_arn="account-admin", technique_chain=["iam:PassRole"], severity="high",
    )
    db_session.add(path)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert graph["edges"][0]["status"] == "open"


async def test_targets_reflects_open_path_count_and_worst_severity(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    db_session.add_all([
        CloudPrivEscPath(
            id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
            source_principal_arn="arn:aws:iam::123456789012:role/a", target_principal_arn="account-admin",
            technique_chain=["iam:PassRole"], severity="medium",
        ),
        CloudPrivEscPath(
            id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
            source_principal_arn="arn:aws:iam::123456789012:role/b", target_principal_arn="account-admin",
            technique_chain=["iam:PassRole"], severity="critical",
        ),
        CloudPrivEscPath(
            id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
            source_principal_arn="arn:aws:iam::123456789012:role/c", target_principal_arn="account-admin",
            technique_chain=["iam:PassRole"], severity="high", status="retest_closed",
        ),
    ])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    [target] = graph["targets"]
    assert target["node_id"] == "account-admin"
    assert target["open_path_count"] == 2
    assert target["closed_path_count"] == 1
    assert target["worst_severity"] == "critical"


async def test_targets_worst_severity_is_none_when_only_severed_paths_reach_it(db_session: AsyncSession):
    # A target reached only by closed paths is real "contained" state, not
    # just filtered out of the response.
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    db_session.add(CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/a", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high", status="retest_closed",
    ))
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    [target] = graph["targets"]
    assert target["open_path_count"] == 0
    assert target["closed_path_count"] == 1
    assert target["worst_severity"] is None


async def test_chokepoint_ranks_the_policy_shared_by_the_most_open_paths(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    shared_policy = "arn:aws:iam::123456789012:policy/over-permissioned"
    db_session.add_all([
        CloudPrivEscPath(
            id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
            source_principal_arn=f"arn:aws:iam::123456789012:role/r{i}", target_principal_arn="account-admin",
            technique_chain=["iam:PassRole"], severity="high", policy_arn=shared_policy, policy_name="over-permissioned-policy",
        )
        for i in range(3)
    ] + [
        CloudPrivEscPath(
            id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
            source_principal_arn="arn:aws:iam::123456789012:role/lone", target_principal_arn="account-admin",
            technique_chain=["iam:PassRole"], severity="high", policy_arn="arn:aws:iam::123456789012:policy/different",
        ),
    ])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert graph["chokepoint"]["policy_arn"] == shared_policy
    assert graph["chokepoint"]["policy_name"] == "over-permissioned-policy"
    assert graph["chokepoint"]["closes_count"] == 3
    assert graph["chokepoint"]["total_open_count"] == 4


async def test_chokepoint_is_none_when_no_policy_is_shared_by_more_than_one_path(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    db_session.add(CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/solo", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high", policy_arn="arn:aws:iam::123456789012:policy/solo",
    ))
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert graph["chokepoint"] is None


async def test_chokepoint_is_none_for_an_empty_graph(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await db_session.commit()
    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert graph["chokepoint"] is None
    assert graph["targets"] == []


# ── Phase 39b: real read-only scope data ────────────────────────────────────

async def test_scope_reports_real_connection_and_iam_principal_counts(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    db_session.add_all([
        CloudAsset(
            id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
            resource_type="iam_role", resource_id="arn:...:role/a", resource_metadata={},
        ),
        CloudAsset(
            id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
            resource_type="iam_user", resource_id="arn:...:user/b", resource_metadata={},
        ),
        # Not an IAM resource — must not count toward iam_principals.
        CloudAsset(
            id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
            resource_type="ec2_instance", resource_id="arn:...:instance/i-x", resource_metadata={},
        ),
    ])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert graph["scope"]["read_only"] is True
    assert graph["scope"]["connected_accounts"] == 1
    assert graph["scope"]["iam_principals"] == 2


async def test_scope_is_zero_for_a_tenant_with_no_connections(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await db_session.commit()
    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert graph["scope"] == {"read_only": True, "connected_accounts": 0, "iam_principals": 0}


async def test_scope_excludes_unconnected_connections(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    connection.status = "revoked"
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert graph["scope"]["connected_accounts"] == 0


# ── Scan/connection selector: real "only this account's real paths", not a
# tenant-wide blend, when a connection_id is given — verified against a
# second real connection on the same tenant, not just an empty-vs-full check. ──

async def _make_second_connection_and_engagement(db_session: AsyncSession, tenant, role_arn: str):
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn=role_arn, external_id="ext-456", status="connected",
    )
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add_all([connection, engagement])
    await db_session.flush()
    return connection, engagement


async def test_build_tenant_privesc_graph_filters_to_one_aws_connection(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    conn_a, eng_a = await _make_connection_and_engagement(db_session, tenant)
    conn_a.display_name = "Production"
    conn_b, eng_b = await _make_second_connection_and_engagement(
        db_session, tenant, "arn:aws:iam::999999999999:role/OtherAccount",
    )

    path_a = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=eng_a.id, cloud_account_connection_id=conn_a.id,
        source_principal_arn="arn:aws:iam::123456789012:role/only-in-a", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high",
    )
    path_b = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=eng_b.id, cloud_account_connection_id=conn_b.id,
        source_principal_arn="arn:aws:iam::999999999999:role/only-in-b", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high",
    )
    db_session.add_all([path_a, path_b])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id, str(conn_a.id))
    node_ids = {n["id"] for n in graph["nodes"]}
    assert "arn:aws:iam::123456789012:role/only-in-a" in node_ids
    assert "arn:aws:iam::999999999999:role/only-in-b" not in node_ids
    assert graph["viewing"] == {"id": str(conn_a.id), "provider": "aws", "label": "Production"}


async def test_build_tenant_privesc_graph_connection_filter_excludes_oauth_edges(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    conn_a, eng_a = await _make_connection_and_engagement(db_session, tenant)
    _oauth_engagement, oauth_connection = await _make_oauth_engagement_and_connection(db_session, tenant)

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=eng_a.id, cloud_account_connection_id=conn_a.id,
        source_principal_arn="arn:aws:iam::123456789012:role/aws-side", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high",
    )
    grant = OAuthGrant(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=_oauth_engagement.id, connection_id=oauth_connection.id,
        grantee_principal="jane@example.com", app_name="Zapier", app_client_id="app-guid-1",
        scopes=["Mail.ReadWrite"], risk_tier="high",
    )
    db_session.add_all([path, grant])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id, str(conn_a.id))
    assert all(n["kind"] != "third_party_app" for n in graph["nodes"])
    assert graph["sources"] == ["IAM Privilege-Escalation Graph (Cloudsplaining)"]


async def test_build_tenant_privesc_graph_filters_to_one_oauth_connection(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    conn_a, eng_a = await _make_connection_and_engagement(db_session, tenant)
    oauth_engagement, oauth_connection = await _make_oauth_engagement_and_connection(db_session, tenant)

    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=eng_a.id, cloud_account_connection_id=conn_a.id,
        source_principal_arn="arn:aws:iam::123456789012:role/aws-side", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high",
    )
    grant = OAuthGrant(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=oauth_engagement.id, connection_id=oauth_connection.id,
        grantee_principal="jane@example.com", app_name="Zapier", app_client_id="app-guid-1",
        scopes=["Mail.ReadWrite"], risk_tier="high",
    )
    db_session.add_all([path, grant])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id, str(oauth_connection.id))
    assert graph["edges"] == [] or all(e.get("priv_esc_path_id") is None for e in graph["edges"])
    assert any(n["kind"] == "third_party_app" for n in graph["nodes"])
    assert not any(n["id"] == "arn:aws:iam::123456789012:role/aws-side" for n in graph["nodes"])
    assert graph["viewing"]["provider"] == "microsoft365"


async def test_build_tenant_privesc_graph_unfiltered_is_unchanged_by_the_new_param(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/x", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high",
    )
    db_session.add(path)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert len(graph["nodes"]) == 2
    assert graph["viewing"] is None


async def test_build_tenant_privesc_graph_connection_id_from_another_tenant_is_empty_not_a_leak(db_session: AsyncSession):
    tenant_a = await make_tenant(db_session, name="Tenant A")
    tenant_b = await make_tenant(db_session, name="Tenant B")
    conn_b, eng_b = await _make_connection_and_engagement(db_session, tenant_b)
    path_b = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant_b.id, engagement_id=eng_b.id, cloud_account_connection_id=conn_b.id,
        source_principal_arn="arn:aws:iam::123456789012:role/only-tenant-b", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high",
    )
    db_session.add(path_b)
    await db_session.commit()

    # Tenant A's own session asking for Tenant B's real connection id must
    # never see Tenant B's data — the tenant_id filter in the lookup itself
    # is what prevents this, not just the eventual query.
    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant_a.id, str(conn_b.id))
    assert graph["nodes"] == []
    assert graph["edges"] == []
    assert graph["viewing"] is None


# ── Real findings with nowhere else to go, surfaced as standalone nodes
# (VPS/host findings, general cloud misconfiguration) — no fabricated edge
# to anything, just a real severity badge on a real, otherwise-orphan node. ──

def _make_host_connection(tenant, hostname: str, display_name: str | None = None) -> HostConnection:
    return HostConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, hostname_or_ip=hostname, ssh_username="audit",
        encrypted_private_key="x", public_key="ssh-ed25519 x", public_key_fingerprint="x",
        status="connected", display_name=display_name,
    )


async def test_build_tenant_privesc_graph_surfaces_a_cloud_resource_node_with_an_open_finding(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123",
        resource_metadata={},
    )
    finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
        tier="cloud", severity="critical", title="SSH open to the internet", status="open",
        check_id="ec2_securitygroup_allow_ingress_from_internet_to_port_22", resource_uid="sg-0xyz",
    )
    db_session.add_all([asset, finding])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    node = next(n for n in graph["nodes"] if n["id"] == asset.resource_id)
    assert node["kind"] == "cloud_resource"
    assert node["open_findings"] == 1
    assert node["findings_worst_severity"] == "critical"
    assert "i-0abc123" in node["label"]
    assert "Cloud Misconfiguration Findings (Prowler)" in graph["sources"]


async def test_build_tenant_privesc_graph_excludes_resources_with_no_open_findings(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-clean",
        resource_metadata={},
    )
    db_session.add(asset)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert graph["nodes"] == []


async def test_build_tenant_privesc_graph_surfaces_a_host_node_with_an_open_finding(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    host = _make_host_connection(tenant, "10.0.0.5", display_name="mail-prod-01")
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="host", status="active")
    db_session.add_all([host, engagement])
    await db_session.flush()
    finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=None,
        tier="host", severity="high", title="Outdated SSH protocol", status="open",
        check_id="SSH-7408", resource_uid="10.0.0.5",
    )
    db_session.add(finding)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    node = next(n for n in graph["nodes"] if n["id"] == "host:10.0.0.5")
    assert node["kind"] == "host"
    assert node["label"] == "mail-prod-01"
    assert node["open_findings"] == 1
    assert node["findings_worst_severity"] == "high"
    assert "Host Vulnerability Findings (Lynis)" in graph["sources"]


async def test_build_tenant_privesc_graph_excludes_hosts_with_no_open_findings(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    host = _make_host_connection(tenant, "10.0.0.6")
    db_session.add(host)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert graph["nodes"] == []


async def test_build_tenant_privesc_graph_connection_filter_isolates_one_resource_node(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    conn_a, eng_a = await _make_connection_and_engagement(db_session, tenant)
    conn_b, eng_b = await _make_second_connection_and_engagement(
        db_session, tenant, "arn:aws:iam::999999999999:role/OtherAccount",
    )
    asset_a = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=conn_a.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-a", resource_metadata={},
    )
    asset_b = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=conn_b.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:999999999999:instance/i-b", resource_metadata={},
    )
    finding_a = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=eng_a.id, asset_id=asset_a.id,
        tier="cloud", severity="high", title="a", status="open", check_id="x", resource_uid="sg-a",
    )
    finding_b = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=eng_b.id, asset_id=asset_b.id,
        tier="cloud", severity="high", title="b", status="open", check_id="x", resource_uid="sg-b",
    )
    db_session.add_all([asset_a, asset_b, finding_a, finding_b])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id, str(conn_a.id))
    node_ids = {n["id"] for n in graph["nodes"]}
    assert asset_a.resource_id in node_ids
    assert asset_b.resource_id not in node_ids


async def test_build_tenant_privesc_graph_host_connection_filter_excludes_everything_else(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    conn_a, eng_a = await _make_connection_and_engagement(db_session, tenant)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=conn_a.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-a", resource_metadata={},
    )
    cloud_finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=eng_a.id, asset_id=asset.id,
        tier="cloud", severity="high", title="a", status="open", check_id="x", resource_uid="sg-a",
    )
    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=eng_a.id, cloud_account_connection_id=conn_a.id,
        source_principal_arn="arn:aws:iam::123456789012:role/x", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high",
    )
    host = _make_host_connection(tenant, "10.0.0.7")
    host_engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="host", status="active")
    db_session.add_all([asset, cloud_finding, path, host, host_engagement])
    await db_session.flush()
    host_finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=host_engagement.id, asset_id=None,
        tier="host", severity="critical", title="h", status="open", check_id="x", resource_uid="10.0.0.7",
    )
    db_session.add(host_finding)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id, str(host.id))
    assert graph["nodes"] == [
        n for n in graph["nodes"] if n["id"] == "host:10.0.0.7"
    ]
    assert len(graph["nodes"]) == 1
    assert graph["viewing"] == {"id": str(host.id), "provider": "host", "label": "10.0.0.7"}


# ── RUNS_AS edges (bridging a Prowler resource node into the IAM graph) ──

async def test_build_tenant_privesc_graph_adds_a_runs_as_edge_for_a_resolved_ec2_role(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    role_arn = "arn:aws:iam::123456789012:role/web-role"
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-web",
        resource_metadata={"role_arn": role_arn},
    )
    db_session.add(asset)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)

    runs_as_edges = [e for e in graph["edges"] if e["edge_type"] == "runs_as"]
    assert len(runs_as_edges) == 1
    edge = runs_as_edges[0]
    assert edge["source"] == asset.resource_id
    assert edge["target"] == role_arn
    assert edge["severity"] == "low"  # no open CloudPrivEscPath for this role — a real but low-risk structural fact
    assert edge["status"] == "open"
    assert edge["remediation"]
    node_ids = {n["id"] for n in graph["nodes"]}
    assert asset.resource_id in node_ids and role_arn in node_ids
    assert "Compute-to-Role Attachments (EC2 Instance Profiles)" in graph["sources"]


async def test_build_tenant_privesc_graph_runs_as_edge_inherits_the_roles_worst_open_privesc_severity(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    role_arn = "arn:aws:iam::123456789012:role/escalatable-role"
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-web",
        resource_metadata={"role_arn": role_arn},
    )
    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn=role_arn, target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical",
    )
    db_session.add_all([asset, path])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)

    runs_as_edge = next(e for e in graph["edges"] if e["edge_type"] == "runs_as")
    assert runs_as_edge["severity"] == "critical"  # inherited from the role's real open privesc path


async def test_build_tenant_privesc_graph_no_runs_as_edge_without_a_resolved_role(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-clean",
        resource_metadata={},  # no role_arn — never scanned as attached to a role
    )
    db_session.add(asset)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert not [e for e in graph["edges"] if e["edge_type"] == "runs_as"]


async def test_build_tenant_privesc_graph_priv_esc_and_oauth_edges_carry_their_own_edge_type(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:role/a", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="high",
    )
    db_session.add(path)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert graph["edges"][0]["edge_type"] == "priv_esc"


# ── EXPOSED_TO_INTERNET edges (real attack entry points) ─────────────────

def test_is_internet_exposed_true_via_categories():
    assert graph_service._is_internet_exposed({"categories": ["internet-exposed"]}) is True


def test_is_internet_exposed_true_via_public_ip():
    assert graph_service._is_internet_exposed({"resource_metadata": {"metadata": {"public_ip": "1.2.3.4"}}}) is True


def test_is_internet_exposed_false_when_neither_signal_present():
    assert graph_service._is_internet_exposed({"categories": [], "resource_metadata": {}}) is False


def test_is_internet_exposed_handles_none_extra():
    assert graph_service._is_internet_exposed(None) is False


async def test_build_tenant_privesc_graph_adds_an_exposed_to_internet_edge(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-exposed",
        resource_metadata={},
    )
    finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
        tier="cloud", severity="high", title="SSH open to the internet", status="open",
        check_id="ec2_securitygroup_allow_ingress_from_internet_to_port_22", resource_uid="sg-x",
        extra={"categories": ["internet-exposed"]},
    )
    db_session.add_all([asset, finding])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)

    exposure_edges = [e for e in graph["edges"] if e["edge_type"] == "exposed_to_internet"]
    assert len(exposure_edges) == 1
    edge = exposure_edges[0]
    assert edge["source"] == "internet"
    assert edge["target"] == asset.resource_id
    assert edge["severity"] == "high"
    assert edge["remediation"]
    node_ids = {n["id"] for n in graph["nodes"]}
    assert "internet" in node_ids and asset.resource_id in node_ids
    assert "Internet-Exposed Resources (Prowler)" in graph["sources"]


async def test_build_tenant_privesc_graph_exposure_edge_uses_worst_severity_among_exposed_findings_only(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-exposed",
        resource_metadata={},
    )
    exposed_low = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
        tier="cloud", severity="low", title="a", status="open", check_id="a", resource_uid="sg-x",
        extra={"categories": ["internet-exposed"]},
    )
    exposed_critical = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
        tier="cloud", severity="critical", title="b", status="open", check_id="b", resource_uid="sg-y",
        extra={"categories": ["internet-exposed"]},
    )
    unrelated_critical = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
        tier="cloud", severity="critical", title="c", status="open", check_id="c", resource_uid="sg-z",
        extra={"categories": []},  # not internet-exposed — must not count toward the edge's severity
    )
    db_session.add_all([asset, exposed_low, exposed_critical, unrelated_critical])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    edge = next(e for e in graph["edges"] if e["edge_type"] == "exposed_to_internet")
    assert edge["severity"] == "critical"  # worst among the two exposed findings, both real signals


async def test_build_tenant_privesc_graph_no_exposure_edge_without_the_signal(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-clean",
        resource_metadata={},
    )
    finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
        tier="cloud", severity="high", title="not exposed", status="open", check_id="x", resource_uid="sg-x",
        extra={"categories": []},
    )
    db_session.add_all([asset, finding])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert not [e for e in graph["edges"] if e["edge_type"] == "exposed_to_internet"]
    assert "internet" not in {n["id"] for n in graph["nodes"]}


async def test_build_tenant_privesc_graph_shares_one_internet_node_across_multiple_exposed_resources(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    asset_a = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-a",
        resource_metadata={},
    )
    asset_b = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-b",
        resource_metadata={},
    )
    finding_a = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset_a.id,
        tier="cloud", severity="high", title="a", status="open", check_id="a", resource_uid="sg-a",
        extra={"categories": ["internet-exposed"]},
    )
    finding_b = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset_b.id,
        tier="cloud", severity="medium", title="b", status="open", check_id="b", resource_uid="sg-b",
        extra={"categories": ["internet-exposed"]},
    )
    db_session.add_all([asset_a, asset_b, finding_a, finding_b])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    exposure_edges = [e for e in graph["edges"] if e["edge_type"] == "exposed_to_internet"]
    assert len(exposure_edges) == 2
    assert {e["source"] for e in exposure_edges} == {"internet"}  # one shared node, not two
    internet_nodes = [n for n in graph["nodes"] if n["id"] == "internet"]
    assert len(internet_nodes) == 1


# ── is_high_value surfaced on graph nodes ─────────────────────────────────

async def test_build_tenant_privesc_graph_surfaces_is_high_value_via_compute_resource_nodes(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="s3_bucket", resource_id="arn:aws:s3:::customer-data",
        resource_metadata={}, is_high_value=True,
    )
    finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
        tier="cloud", severity="high", title="public bucket", status="open", check_id="x", resource_uid="x",
    )
    db_session.add_all([asset, finding])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    node = next(n for n in graph["nodes"] if n["id"] == asset.resource_id)
    assert node["is_high_value"] is True


async def test_build_tenant_privesc_graph_surfaces_is_high_value_via_runs_as(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-web",
        resource_metadata={"role_arn": "arn:aws:iam::123456789012:role/web-role"}, is_high_value=True,
    )
    db_session.add(asset)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    node = next(n for n in graph["nodes"] if n["id"] == asset.resource_id)
    assert node["is_high_value"] is True


async def test_build_tenant_privesc_graph_surfaces_is_high_value_via_exposed_to_internet(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="rds_db_instance", resource_id="arn:aws:rds:us-east-1:123456789012:db:prod-db",
        resource_metadata={}, is_high_value=True,
    )
    finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
        tier="cloud", severity="critical", title="publicly accessible", status="open", check_id="x", resource_uid="x",
        extra={"categories": ["internet-exposed"]},
    )
    db_session.add_all([asset, finding])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    node = next(n for n in graph["nodes"] if n["id"] == asset.resource_id)
    assert node["is_high_value"] is True


async def test_build_tenant_privesc_graph_is_high_value_defaults_false(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-plain",
        resource_metadata={}, is_high_value=False,
    )
    finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
        tier="cloud", severity="low", title="a", status="open", check_id="x", resource_uid="x",
    )
    db_session.add_all([asset, finding])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    node = next(n for n in graph["nodes"] if n["id"] == asset.resource_id)
    assert node["is_high_value"] is False


# ── LATERAL_MOVEMENT edges (same-VPC SG-to-SG reachability) ──────────────

def test_attack_techniques_for_lateral_movement_returns_a_real_fixed_technique():
    techniques = attack_techniques_for_lateral_movement()
    assert techniques == [{"id": "T1021", "name": "Remote Services", "tactics": ["Lateral Movement"]}]


def test_lateral_movement_severity_high_for_a_sensitive_port():
    assert graph_service._lateral_movement_severity(3306) == "high"
    assert graph_service._lateral_movement_severity(22) == "high"


def test_lateral_movement_severity_medium_for_an_arbitrary_port():
    assert graph_service._lateral_movement_severity(8080) == "medium"
    assert graph_service._lateral_movement_severity(None) == "medium"


def _make_sg_asset(tenant_id, connection_id, group_id, referenced_group_ids, ingress_rules, region="eu-north-1"):
    return CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant_id, cloud_account_connection_id=connection_id,
        resource_type="ec2_security_group", resource_id=f"arn:aws:ec2:{region}:123456789012:security-group/{group_id}",
        region=region, resource_metadata={"ingress_rules": ingress_rules, "referenced_group_ids": referenced_group_ids},
    )


def _make_instance_asset(tenant_id, connection_id, instance_id, security_group_ids, region="eu-north-1"):
    return CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant_id, cloud_account_connection_id=connection_id,
        resource_type="ec2_instance", resource_id=f"arn:aws:ec2:{region}:123456789012:instance/{instance_id}",
        region=region, resource_metadata={"security_group_ids": security_group_ids},
    )


async def test_build_tenant_privesc_graph_adds_a_lateral_movement_edge_for_a_real_sg_reference(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    web = _make_instance_asset(tenant.id, connection.id, "i-web", ["sg-web"])
    db_asset = _make_instance_asset(tenant.id, connection.id, "i-db", ["sg-db"])
    db_sg = _make_sg_asset(
        tenant.id, connection.id, "sg-db", ["sg-web"],
        [{"protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidrs": [], "referenced_group_ids": ["sg-web"]}],
    )
    db_session.add_all([web, db_asset, db_sg])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)

    lateral_edges = [e for e in graph["edges"] if e["edge_type"] == "lateral_movement"]
    assert len(lateral_edges) == 1
    edge = lateral_edges[0]
    assert edge["source"] == web.resource_id
    assert edge["target"] == db_asset.resource_id
    assert edge["severity"] == "high"  # port 5432 is a well-known DB port
    assert edge["remediation"]
    node_ids = {n["id"] for n in graph["nodes"]}
    assert web.resource_id in node_ids and db_asset.resource_id in node_ids


async def test_build_tenant_privesc_graph_lateral_movement_uses_medium_for_an_arbitrary_port(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    web = _make_instance_asset(tenant.id, connection.id, "i-web", ["sg-web"])
    app = _make_instance_asset(tenant.id, connection.id, "i-app", ["sg-app"])
    app_sg = _make_sg_asset(
        tenant.id, connection.id, "sg-app", ["sg-web"],
        [{"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidrs": [], "referenced_group_ids": ["sg-web"]}],
    )
    db_session.add_all([web, app, app_sg])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    edge = next(e for e in graph["edges"] if e["edge_type"] == "lateral_movement")
    assert edge["severity"] == "medium"


async def test_build_tenant_privesc_graph_no_lateral_movement_edge_without_a_real_sg_reference(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    web = _make_instance_asset(tenant.id, connection.id, "i-web", ["sg-web"])
    other = _make_instance_asset(tenant.id, connection.id, "i-other", ["sg-other"])
    other_sg = _make_sg_asset(tenant.id, connection.id, "sg-other", [], [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": ["10.0.0.0/8"], "referenced_group_ids": []}])
    db_session.add_all([web, other, other_sg])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert not [e for e in graph["edges"] if e["edge_type"] == "lateral_movement"]


async def test_build_tenant_privesc_graph_no_self_loop_when_sg_references_itself(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    instance = _make_instance_asset(tenant.id, connection.id, "i-solo", ["sg-solo"])
    solo_sg = _make_sg_asset(
        tenant.id, connection.id, "sg-solo", ["sg-solo"],
        [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": [], "referenced_group_ids": ["sg-solo"]}],
    )
    db_session.add_all([instance, solo_sg])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert not [e for e in graph["edges"] if e["edge_type"] == "lateral_movement"]


def test_attack_techniques_for_can_access_returns_a_real_fixed_technique():
    techniques = attack_techniques_for_can_access()
    assert techniques == [{"id": "T1530", "name": "Data from Cloud Storage", "tactics": ["Collection"]}]


def test_can_access_severity_critical_for_a_destructive_action():
    assert graph_service._can_access_severity(["s3:GetObject", "s3:PutObject"]) == "critical"
    assert graph_service._can_access_severity(["s3:DeleteObject"]) == "critical"


def test_can_access_severity_high_for_real_content_read():
    assert graph_service._can_access_severity(["s3:GetObject", "s3:ListBucket"]) == "high"
    assert graph_service._can_access_severity(["s3:GetObject"]) == "high"


def test_can_access_severity_medium_for_listing_only():
    # A real, live-verified distinction: several AWS-managed policies
    # (including ViewOnlyAccess itself) grant s3:ListBucket broadly —
    # that proves enumeration only, not real content access, and must
    # not be labeled the same severity as a GetObject grant.
    assert graph_service._can_access_severity(["s3:ListBucket"]) == "medium"


def _make_principal_asset(tenant_id, connection_id, principal_arn, can_access=None, resource_type="iam_role"):
    return CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant_id, cloud_account_connection_id=connection_id,
        resource_type=resource_type, resource_id=principal_arn,
        resource_metadata={"can_access": can_access} if can_access else {},
    )


def _make_bucket_asset(tenant_id, connection_id, bucket_name, is_high_value=True):
    return CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant_id, cloud_account_connection_id=connection_id,
        resource_type="s3_bucket", resource_id=f"arn:aws:s3:::{bucket_name}",
        resource_metadata={}, is_high_value=is_high_value,
    )


async def test_build_tenant_privesc_graph_adds_a_can_access_edge_for_a_real_grant(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    bucket = _make_bucket_asset(tenant.id, connection.id, "customer-data")
    role = _make_principal_asset(
        tenant.id, connection.id, "arn:aws:iam::123456789012:role/data-reader",
        can_access=[{"resource_arn": bucket.resource_id, "resource_type": "s3_bucket", "actions_allowed": ["s3:GetObject", "s3:ListBucket"]}],
    )
    db_session.add_all([bucket, role])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)

    can_access_edges = [e for e in graph["edges"] if e["edge_type"] == "can_access"]
    assert len(can_access_edges) == 1
    edge = can_access_edges[0]
    assert edge["source"] == role.resource_id
    assert edge["target"] == bucket.resource_id
    assert edge["severity"] == "high"
    assert edge["remediation"]
    # The bucket has zero open Findings — proves _ensure_node was called
    # directly for it (matching RUNS_AS/EXPOSED_TO_INTERNET/lateral_movement's
    # own precedent), not left to _compute_resource_nodes, which would
    # never have surfaced a "clean" resource at all.
    bucket_node = next(n for n in graph["nodes"] if n["id"] == bucket.resource_id)
    assert bucket_node["is_high_value"] is True


async def test_build_tenant_privesc_graph_can_access_edge_severity_critical_for_write_grant(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    bucket = _make_bucket_asset(tenant.id, connection.id, "customer-data")
    role = _make_principal_asset(
        tenant.id, connection.id, "arn:aws:iam::123456789012:role/data-writer",
        can_access=[{"resource_arn": bucket.resource_id, "resource_type": "s3_bucket", "actions_allowed": ["s3:GetObject", "s3:PutObject"]}],
    )
    db_session.add_all([bucket, role])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    edge = next(e for e in graph["edges"] if e["edge_type"] == "can_access")
    assert edge["severity"] == "critical"


async def test_build_tenant_privesc_graph_no_can_access_edge_when_bucket_asset_missing(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    # References a bucket ARN with no matching CloudAsset row at all —
    # must degrade to no edge, not a crash or a fabricated node.
    role = _make_principal_asset(
        tenant.id, connection.id, "arn:aws:iam::123456789012:role/data-reader",
        can_access=[{"resource_arn": "arn:aws:s3:::ghost-bucket", "resource_type": "s3_bucket", "actions_allowed": ["s3:GetObject"]}],
    )
    db_session.add(role)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert not [e for e in graph["edges"] if e["edge_type"] == "can_access"]


async def test_build_tenant_privesc_graph_no_can_access_edge_without_a_grant(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    bucket = _make_bucket_asset(tenant.id, connection.id, "customer-data")
    role = _make_principal_asset(tenant.id, connection.id, "arn:aws:iam::123456789012:role/no-access")
    db_session.add_all([bucket, role])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert not [e for e in graph["edges"] if e["edge_type"] == "can_access"]


# ── Port-level EXPOSED_TO_INTERNET evidence for EC2 instances ─────────────

def test_internet_exposure_port_severity_critical_for_a_sensitive_port():
    assert graph_service._internet_exposure_port_severity(22) == "critical"
    assert graph_service._internet_exposure_port_severity(3389) == "critical"


def test_internet_exposure_port_severity_high_for_an_arbitrary_port():
    assert graph_service._internet_exposure_port_severity(8080) == "high"
    assert graph_service._internet_exposure_port_severity(None) == "high"


async def test_build_tenant_privesc_graph_port_based_exposure_with_zero_findings(db_session: AsyncSession):
    # The real detection-gap case this change closes: no Prowler Finding
    # at all, but a real SG rule open to the raw internet on a sensitive
    # port — must still produce a real exposed_to_internet edge.
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    instance = _make_instance_asset(tenant.id, connection.id, "i-open", ["sg-open"])
    sg = _make_sg_asset(
        tenant.id, connection.id, "sg-open", [],
        [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": ["0.0.0.0/0"], "referenced_group_ids": []}],
    )
    db_session.add_all([instance, sg])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    exposure_edges = [e for e in graph["edges"] if e["edge_type"] == "exposed_to_internet"]
    assert len(exposure_edges) == 1
    edge = exposure_edges[0]
    assert edge["source"] == "internet"
    assert edge["target"] == instance.resource_id
    assert edge["severity"] == "critical"  # port 22 is a well-known sensitive port
    # Real evidence for the graph's evidence panel, not just severity.
    assert edge["exposed_ports"] == [{"port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0"}]


async def test_build_tenant_privesc_graph_port_based_exposure_arbitrary_port_is_high(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    instance = _make_instance_asset(tenant.id, connection.id, "i-open", ["sg-open"])
    sg = _make_sg_asset(
        tenant.id, connection.id, "sg-open", [],
        [{"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidrs": ["0.0.0.0/0"], "referenced_group_ids": []}],
    )
    db_session.add_all([instance, sg])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    edge = next(e for e in graph["edges"] if e["edge_type"] == "exposed_to_internet")
    assert edge["severity"] == "high"
    assert edge["exposed_ports"] == [{"port": 8080, "protocol": "tcp", "cidr": "0.0.0.0/0"}]


async def test_build_tenant_privesc_graph_multiple_real_open_ports_all_captured(db_session: AsyncSession):
    # The real gap this session found: SEDAC-DEV has THREE real ports open
    # to the internet (22, 80, 443) — the previous "keep only the worst"
    # version silently dropped 80 and 443. All three must survive now,
    # with severity still driven by the sensitive one (22 -> critical).
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    instance = _make_instance_asset(tenant.id, connection.id, "i-multi", ["sg-multi"])
    sg = _make_sg_asset(
        tenant.id, connection.id, "sg-multi", [],
        [
            {"protocol": "tcp", "from_port": 80, "to_port": 80, "cidrs": ["0.0.0.0/0"], "referenced_group_ids": []},
            {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": ["0.0.0.0/0"], "referenced_group_ids": []},
            {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidrs": ["0.0.0.0/0"], "referenced_group_ids": []},
        ],
    )
    db_session.add_all([instance, sg])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    edge = next(e for e in graph["edges"] if e["edge_type"] == "exposed_to_internet")
    assert edge["severity"] == "critical"  # still driven by port 22, the sensitive one
    ports = {p["port"] for p in edge["exposed_ports"]}
    assert ports == {80, 22, 443}


async def test_build_tenant_privesc_graph_finding_only_exposure_has_no_port_evidence(db_session: AsyncSession):
    # No security-group data at all for this asset — the Finding-based
    # signal alone must not fabricate port evidence that was never real.
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-finding-only",
        resource_metadata={},
    )
    finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
        tier="cloud", severity="high", title="SSH open to the internet", status="open",
        check_id="ec2_securitygroup_allow_ingress_from_internet_to_port_22", resource_uid="sg-x",
        extra={"categories": ["internet-exposed"]},
    )
    db_session.add_all([asset, finding])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    edge = next(e for e in graph["edges"] if e["edge_type"] == "exposed_to_internet")
    assert edge["exposed_ports"] == []


async def test_build_tenant_privesc_graph_no_port_based_exposure_when_scoped_to_another_sg(db_session: AsyncSession):
    # A rule referencing another security group (not the raw internet) —
    # real evidence for LATERAL_MOVEMENT, not for EXPOSED_TO_INTERNET.
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    instance = _make_instance_asset(tenant.id, connection.id, "i-scoped", ["sg-scoped"])
    sg = _make_sg_asset(
        tenant.id, connection.id, "sg-scoped", ["sg-other"],
        [{"protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidrs": [], "referenced_group_ids": ["sg-other"]}],
    )
    db_session.add_all([instance, sg])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    assert not [e for e in graph["edges"] if e["edge_type"] == "exposed_to_internet"]


async def test_build_tenant_privesc_graph_exposure_takes_worst_of_finding_and_port_signals(db_session: AsyncSession):
    # Both signals present for the same asset — exactly one edge, at the
    # genuinely worst severity, not two competing edges.
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    instance = _make_instance_asset(tenant.id, connection.id, "i-both", ["sg-both"])
    sg = _make_sg_asset(
        tenant.id, connection.id, "sg-both", [],
        [{"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidrs": ["0.0.0.0/0"], "referenced_group_ids": []}],
    )
    finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=instance.id,
        tier="cloud", severity="low", title="weak signal", status="open", check_id="a", resource_uid="sg-both",
        extra={"categories": ["internet-exposed"]},
    )
    db_session.add_all([instance, sg, finding])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    exposure_edges = [e for e in graph["edges"] if e["edge_type"] == "exposed_to_internet"]
    assert len(exposure_edges) == 1
    # Finding severity is "low", port-based severity for an arbitrary port is "high" — worst wins.
    assert exposure_edges[0]["severity"] == "high"


# ── Kill Chain Narrative — real entry-to-outcome hop assembly ─────────────

async def test_compute_kill_chains_produces_the_full_internet_to_admin_and_data_chain(db_session: AsyncSession):
    # The exact real shape this session live-verified: internet-exposed EC2
    # -> runs_as role -> BOTH a real priv_esc to account-admin AND a real
    # CAN_ACCESS to a tagged crown-jewel bucket, from the same principal.
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    role_arn = "arn:aws:iam::131189842899:role/sentinel-runs-as-demo"

    instance = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:eu-north-1:131189842899:instance/i-kill-chain",
        resource_metadata={"role_arn": role_arn, "security_group_ids": ["sg-kc"]},
    )
    sg = _make_sg_asset(
        tenant.id, connection.id, "sg-kc", [],
        [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": ["0.0.0.0/0"], "referenced_group_ids": []}],
    )
    bucket = _make_bucket_asset(tenant.id, connection.id, "customer-data")
    bucket.resource_metadata = {"tags": {"DataClassification": "customer-pii"}}
    role_principal = _make_principal_asset(
        tenant.id, connection.id, role_arn,
        can_access=[{"resource_arn": bucket.resource_id, "resource_type": "s3_bucket", "actions_allowed": ["s3:GetObject"]}],
    )
    priv_esc = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, cloud_account_connection_id=connection.id,
        source_principal_arn=role_arn, target_principal_arn="account-admin",
        severity="critical", status="open", technique_chain=["iam:PassRole"],
        discovered_at=engagement.created_at,
    )
    db_session.add_all([instance, sg, bucket, role_principal, priv_esc])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    chains = await graph_service._compute_kill_chains(db_session, graph["nodes"], graph["edges"])

    assert len(chains) == 2
    by_target = {c["target_id"]: c for c in chains}
    assert "account-admin" in by_target
    assert bucket.resource_id in by_target

    admin_chain = by_target["account-admin"]
    assert admin_chain["outcome"] == "Full AWS account administrative control"
    assert [h["edge_type"] for h in admin_chain["hops"]] == ["exposed_to_internet", "runs_as", "priv_esc"]
    assert admin_chain["hops"][0]["source"] == "internet"
    assert admin_chain["chain_severity"] == "critical"

    data_chain = by_target[bucket.resource_id]
    assert "customer-pii" in data_chain["outcome"]
    assert [h["edge_type"] for h in data_chain["hops"]] == ["exposed_to_internet", "runs_as", "can_access"]


async def test_compute_kill_chains_empty_when_no_internet_node(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection, _engagement = await _make_connection_and_engagement(db_session, tenant)
    bucket = _make_bucket_asset(tenant.id, connection.id, "isolated-bucket")
    db_session.add(bucket)
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    chains = await graph_service._compute_kill_chains(db_session, graph["nodes"], graph["edges"])
    assert chains == []


async def test_compute_kill_chains_excludes_unreachable_high_value_targets(db_session: AsyncSession):
    # A real, tagged crown jewel with no edge connecting it to "internet" at
    # all must never appear in a kill chain — no proven path exists.
    tenant = await make_tenant(db_session)
    connection, engagement = await _make_connection_and_engagement(db_session, tenant)
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-exposed",
        resource_metadata={},
    )
    finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id, asset_id=asset.id,
        tier="cloud", severity="high", title="exposed", status="open", check_id="a", resource_uid="sg-x",
        extra={"categories": ["internet-exposed"]},
    )
    isolated_bucket = _make_bucket_asset(tenant.id, connection.id, "isolated-bucket")
    db_session.add_all([asset, finding, isolated_bucket])
    await db_session.commit()

    graph = await graph_service.build_tenant_privesc_graph(db_session, tenant.id)
    chains = await graph_service._compute_kill_chains(db_session, graph["nodes"], graph["edges"])
    target_ids = {c["target_id"] for c in chains}
    assert isolated_bucket.resource_id not in target_ids


def test_kill_chain_outcome_text_for_account_admin():
    assert graph_service._kill_chain_outcome_text("account-admin", {}, {}) == "Full AWS account administrative control"


def test_kill_chain_outcome_text_uses_real_tag_when_present():
    text = graph_service._kill_chain_outcome_text(
        "arn:aws:s3:::x", {"label": "S3 bucket x"}, {"DataClassification": "customer-pii"},
    )
    assert "customer-pii" in text
    assert "S3 bucket x" in text


def test_kill_chain_outcome_text_generic_fallback_without_a_tag():
    text = graph_service._kill_chain_outcome_text("arn:aws:s3:::x", {"label": "S3 bucket x"}, {})
    assert text == "Access to S3 bucket x (tagged high-value)"
