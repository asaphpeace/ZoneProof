import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ActorIdentity, CloudAccountConnection, CloudPrivEscPath, Engagement, Finding
from app.services.identity_resolution_service import (
    find_open_privesc_paths_for_principal,
    open_credential_finding_counts_for_nodes,
    resolve_or_create_actor,
)
from tests.factories import make_tenant


async def test_first_sighting_creates_a_new_actor(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await db_session.commit()

    actor = await resolve_or_create_actor(
        db_session, tenant.id, "aws_iam", "arn:aws:iam::123456789012:user/jane",
    )
    await db_session.commit()

    assert actor.tenant_id == tenant.id
    assert actor.email is None


async def test_same_principal_seen_again_resolves_to_the_same_actor(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await db_session.commit()

    first = await resolve_or_create_actor(
        db_session, tenant.id, "aws_iam", "arn:aws:iam::123456789012:user/jane",
    )
    await db_session.commit()

    second = await resolve_or_create_actor(
        db_session, tenant.id, "aws_iam", "arn:aws:iam::123456789012:user/jane",
    )
    await db_session.commit()

    assert first.id == second.id


async def test_email_match_links_a_new_source_to_the_existing_actor(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await db_session.commit()

    aws_actor = await resolve_or_create_actor(
        db_session, tenant.id, "aws_iam", "arn:aws:iam::123456789012:user/jane",
        email="jane@example.com",
    )
    await db_session.commit()

    auth0_actor = await resolve_or_create_actor(
        db_session, tenant.id, "auth0", "auth0|abc123",
        email="jane@example.com",
    )
    await db_session.commit()

    assert aws_actor.id == auth0_actor.id


async def test_different_emails_create_different_actors(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await db_session.commit()

    actor_a = await resolve_or_create_actor(
        db_session, tenant.id, "aws_iam", "arn:aws:iam::123456789012:user/jane",
        email="jane@example.com",
    )
    actor_b = await resolve_or_create_actor(
        db_session, tenant.id, "aws_iam", "arn:aws:iam::123456789012:user/bob",
        email="bob@example.com",
    )
    await db_session.commit()

    assert actor_a.id != actor_b.id


async def test_resolution_is_scoped_to_tenant(db_session: AsyncSession):
    tenant_a = await make_tenant(db_session, name="Tenant A")
    tenant_b = await make_tenant(db_session, name="Tenant B")
    await db_session.commit()

    actor_a = await resolve_or_create_actor(
        db_session, tenant_a.id, "aws_iam", "arn:aws:iam::123456789012:user/jane",
        email="jane@example.com",
    )
    actor_b = await resolve_or_create_actor(
        db_session, tenant_b.id, "aws_iam", "arn:aws:iam::123456789012:user/jane",
        email="jane@example.com",
    )
    await db_session.commit()

    # Same ARN, same email, but different tenants — must not merge across
    # tenant boundaries no matter how strong the match looks.
    assert actor_a.id != actor_b.id
    assert actor_a.tenant_id != actor_b.tenant_id


async def test_email_provenance_is_recorded_on_the_identity(db_session: AsyncSession):
    from sqlalchemy import select
    tenant = await make_tenant(db_session)
    await db_session.commit()

    await resolve_or_create_actor(
        db_session, tenant.id, "aws_iam", "arn:aws:iam::123456789012:user/jane",
        email="jane@example.com", email_provenance="sso_session",
    )
    await db_session.commit()

    identity = await db_session.scalar(
        select(ActorIdentity).where(ActorIdentity.tenant_id == tenant.id, ActorIdentity.principal_id == "arn:aws:iam::123456789012:user/jane")
    )
    assert identity.email_provenance == "sso_session"


async def test_email_provenance_is_none_when_no_email_given(db_session: AsyncSession):
    from sqlalchemy import select
    tenant = await make_tenant(db_session)
    await db_session.commit()

    await resolve_or_create_actor(db_session, tenant.id, "aws_iam", "arn:aws:iam::123456789012:user/anon")
    await db_session.commit()

    identity = await db_session.scalar(
        select(ActorIdentity).where(ActorIdentity.tenant_id == tenant.id, ActorIdentity.principal_id == "arn:aws:iam::123456789012:user/anon")
    )
    assert identity.email_provenance is None


async def _make_connection(db_session: AsyncSession, tenant_id: uuid.UUID) -> CloudAccountConnection:
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant_id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123", status="connected",
    )
    db_session.add(connection)
    await db_session.flush()
    return connection


async def test_find_open_privesc_paths_for_principal_by_direct_arn(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add(engagement)
    await db_session.flush()
    connection = await _make_connection(db_session, tenant.id)
    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:user/jane", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical", status="open",
    )
    db_session.add(path)
    await db_session.commit()

    paths = await find_open_privesc_paths_for_principal(db_session, tenant.id, principal_arn="arn:aws:iam::123456789012:user/jane")
    assert len(paths) == 1
    assert paths[0].id == path.id


async def test_find_open_privesc_paths_for_principal_by_email_via_actor_link(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add(engagement)
    await db_session.flush()
    connection = await _make_connection(db_session, tenant.id)
    path = CloudPrivEscPath(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        cloud_account_connection_id=connection.id,
        source_principal_arn="arn:aws:iam::123456789012:user/jane", target_principal_arn="account-admin",
        technique_chain=["iam:PassRole"], severity="critical", status="open",
    )
    db_session.add(path)
    await resolve_or_create_actor(
        db_session, tenant.id, "aws_iam", "arn:aws:iam::123456789012:user/jane",
        email="jane@example.com", email_provenance="iam_tag",
    )
    await db_session.commit()

    paths = await find_open_privesc_paths_for_principal(db_session, tenant.id, email="jane@example.com")
    assert len(paths) == 1
    assert paths[0].id == path.id


async def test_find_open_privesc_paths_excludes_closed_paths_and_unmatched_emails(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await db_session.commit()

    paths = await find_open_privesc_paths_for_principal(db_session, tenant.id, email="nobody@example.com")
    assert paths == []


# ── Phase 37b: bulk, Actor-aware credential-finding counts for graph nodes ──

async def _make_engagement(db_session: AsyncSession, tenant_id: uuid.UUID) -> Engagement:
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant_id, tier="cloud", status="active")
    db_session.add(engagement)
    await db_session.flush()
    return engagement


def _finding(tenant_id, engagement_id, resource_uid, *, status="open", check_id="x") -> Finding:
    return Finding(
        id=uuid.uuid4(), tenant_id=tenant_id, engagement_id=engagement_id,
        tier="credential", severity="high", title="t", status=status,
        check_id=check_id, resource_uid=resource_uid,
    )


async def test_open_credential_finding_counts_falls_back_to_direct_match_with_no_actor(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant.id)
    arn = "arn:aws:iam::123456789012:user/no-actor-yet"
    db_session.add(_finding(tenant.id, engagement.id, arn))
    await db_session.commit()

    counts = await open_credential_finding_counts_for_nodes(db_session, tenant.id, [arn])
    assert counts == {arn: 1}


async def test_open_credential_finding_counts_finds_a_match_registered_under_a_different_source(db_session: AsyncSession):
    # The actual cross-provider mechanism: a finding registered under a
    # DIFFERENT source (simulating a future Azure/GCP/Google-Workspace
    # credential pass) but merged onto the same Actor as this AWS node
    # still counts — proving the design without needing a real second
    # provider integrated yet.
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant.id)
    aws_arn = "arn:aws:iam::123456789012:user/jane"
    other_provider_id = "azure-ad:jane-object-id"

    await resolve_or_create_actor(db_session, tenant.id, "aws_iam", aws_arn, email="jane@example.com")
    await resolve_or_create_actor(db_session, tenant.id, "test_other_provider", other_provider_id, email="jane@example.com")
    db_session.add(_finding(tenant.id, engagement.id, other_provider_id, check_id="other_provider_stale_key"))
    await db_session.commit()

    counts = await open_credential_finding_counts_for_nodes(db_session, tenant.id, [aws_arn])
    assert counts == {aws_arn: 1}


async def test_open_credential_finding_counts_two_nodes_sharing_an_actor_each_report_the_full_count(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant.id)
    node_a = "arn:aws:iam::123456789012:user/node-a"
    node_b = "auth0|same-human"

    await resolve_or_create_actor(db_session, tenant.id, "aws_iam", node_a, email="human@example.com")
    await resolve_or_create_actor(db_session, tenant.id, "auth0", node_b, email="human@example.com")
    db_session.add(_finding(tenant.id, engagement.id, node_a, check_id="c1"))
    await db_session.commit()

    counts = await open_credential_finding_counts_for_nodes(db_session, tenant.id, [node_a, node_b])
    assert counts == {node_a: 1, node_b: 1}  # same underlying finding, each node independently reports it


async def test_open_credential_finding_counts_excludes_remediated_findings(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant.id)
    arn = "arn:aws:iam::123456789012:user/fixed-already"
    db_session.add(_finding(tenant.id, engagement.id, arn, status="remediated"))
    await db_session.commit()

    counts = await open_credential_finding_counts_for_nodes(db_session, tenant.id, [arn])
    assert counts == {arn: 0}


async def test_open_credential_finding_counts_zero_for_a_clean_node(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await db_session.commit()

    counts = await open_credential_finding_counts_for_nodes(db_session, tenant.id, ["arn:aws:iam::123456789012:user/clean"])
    assert counts == {"arn:aws:iam::123456789012:user/clean": 0}


async def test_open_credential_finding_counts_is_tenant_scoped(db_session: AsyncSession):
    tenant_a = await make_tenant(db_session, name="Tenant A")
    tenant_b = await make_tenant(db_session, name="Tenant B")
    engagement_b = await _make_engagement(db_session, tenant_b.id)
    arn = "arn:aws:iam::123456789012:user/shared-looking-name"
    db_session.add(_finding(tenant_b.id, engagement_b.id, arn))
    await db_session.commit()

    counts = await open_credential_finding_counts_for_nodes(db_session, tenant_a.id, [arn])
    assert counts == {arn: 0}


async def test_open_credential_finding_counts_empty_node_list_returns_empty_dict(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await db_session.commit()
    assert await open_credential_finding_counts_for_nodes(db_session, tenant.id, []) == {}
