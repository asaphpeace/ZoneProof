"""
Resolves a raw per-source principal (an AWS ARN, an Auth0 user_id) to a
single Actor — a human identity that can span multiple systems. See
ITDR_DESIGN.md Section 2.1 for why this exists: without it, the same
person's activity in two different systems produces two disconnected
records that never get correlated, defeating the entire "follow them
around" premise.

Resolution strategy, in order of confidence — never auto-merge on a weak
signal, since a wrong merge silently attributes one person's activity to
another, which is worse than not merging at all:
  1. Exact match on (tenant_id, source, principal_id) — we've already seen
     this exact principal before, return its known Actor.
  2. Email match — if this principal's email matches an existing Actor's
     email, link this new identity to that Actor (resolved_via=email_match).
  3. First sighting — no match at all, create a brand new Actor
     (resolved_via=first_seen).

Federation-claim resolution (the strongest signal — a direct technical
link when an AWS role was assumed via Auth0 SAML/OIDC federation) and
manual customer-confirmed merges are real resolved_via values in the
schema but are not implemented by this function yet — both need a real
data source (federation claims aren't available from CloudTrail's basic
LookupEvents shape) or a UI (manual merge), neither of which exists yet.
"""
import uuid
from collections import defaultdict

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Actor, ActorIdentity, CloudPrivEscPath, Finding


async def resolve_or_create_actor(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    source: str,
    principal_id: str,
    email: str | None = None,
    email_provenance: str | None = None,
) -> Actor:
    """email_provenance ("sso_session" | "iam_tag") records how confident
    the derived email is — set once at creation on the ActorIdentity row,
    never silently overwritten on a later call for the same identity, so
    a UI can show the real confidence level instead of a single collapsed
    "verified" state (Coverage Map plan phishing transformation, Phase 7)."""
    existing_identity = await db.scalar(
        select(ActorIdentity).where(
            ActorIdentity.tenant_id == tenant_id,
            ActorIdentity.source == source,
            ActorIdentity.principal_id == principal_id,
        )
    )
    if existing_identity:
        actor = await db.get(Actor, existing_identity.actor_id)
        return actor

    resolved_via = "first_seen"
    actor: Actor | None = None

    if email:
        actor = await db.scalar(
            select(Actor).where(Actor.tenant_id == tenant_id, Actor.email == email)
        )
        if actor:
            resolved_via = "email_match"

    if not actor:
        actor = Actor(id=uuid.uuid4(), tenant_id=tenant_id, email=email)
        db.add(actor)
        await db.flush()

    identity = ActorIdentity(
        id=uuid.uuid4(), tenant_id=tenant_id, actor_id=actor.id,
        source=source, principal_id=principal_id, resolved_via=resolved_via,
        email_provenance=email_provenance if email else None,
    )
    db.add(identity)
    await db.flush()
    return actor


async def find_open_privesc_paths_for_principal(
    db: AsyncSession, tenant_id: uuid.UUID, *, principal_arn: str | None = None, email: str | None = None,
) -> list[CloudPrivEscPath]:
    """Given either a known ARN or an email, find every open
    CloudPrivEscPath where that principal is the source or target — the
    query behind "this person who clicked also has these open privilege-
    escalation paths" (Coverage Map plan phishing transformation, Phase 8).
    Deliberately does not assume CloudPrivEscPath stores an actor_id (it
    doesn't) — the join always goes back through Actor/ActorIdentity, the
    same "don't invent a link that isn't there" principle graph_service.py
    already follows for its OAuth-to-IAM merge."""
    arns: set[str] = set()
    if principal_arn:
        arns.add(principal_arn)

    if email:
        actor = await db.scalar(select(Actor).where(Actor.tenant_id == tenant_id, Actor.email == email))
        if actor:
            identity_result = await db.execute(
                select(ActorIdentity.principal_id).where(
                    ActorIdentity.tenant_id == tenant_id, ActorIdentity.actor_id == actor.id,
                    ActorIdentity.source == "aws_iam",
                )
            )
            arns.update(row[0] for row in identity_result.all())

    if not arns:
        return []

    result = await db.execute(
        select(CloudPrivEscPath).where(
            CloudPrivEscPath.tenant_id == tenant_id, CloudPrivEscPath.status == "open",
            (CloudPrivEscPath.source_principal_arn.in_(arns) | CloudPrivEscPath.target_principal_arn.in_(arns)),
        )
    )
    return list(result.scalars().all())


async def _actor_sibling_principals_for_nodes(
    db: AsyncSession, tenant_id: uuid.UUID, node_ids: list[str],
) -> dict[str, set[str]]:
    """Shared resolution step behind both open_credential_finding_counts_
    for_nodes and open_policy_risk_finding_summaries_for_nodes: for each
    node id, the full set of principal_ids to treat as "the same identity"
    when summing Finding rows — every sibling ActorIdentity across ALL
    sources (not just aws_iam) when the node has a resolved Actor, or just
    the node id itself when it doesn't (a third-party-app node, never
    ARN-shaped and never actor-registered; or an AWS principal whose scan
    pass hasn't registered it yet — the exact-match fallback, so nothing
    regresses just because Actor registration hasn't caught up). Two
    queries regardless of len(node_ids), not N+1."""
    if not node_ids:
        return {}

    node_to_actor: dict[str, uuid.UUID] = dict(
        (row.principal_id, row.actor_id)
        for row in (
            await db.execute(
                select(ActorIdentity.principal_id, ActorIdentity.actor_id).where(
                    ActorIdentity.tenant_id == tenant_id, ActorIdentity.principal_id.in_(node_ids),
                )
            )
        ).all()
    )

    actor_ids = set(node_to_actor.values())
    actor_to_principals: dict[uuid.UUID, set[str]] = defaultdict(set)
    if actor_ids:
        for row in (
            await db.execute(
                select(ActorIdentity.actor_id, ActorIdentity.principal_id).where(
                    ActorIdentity.tenant_id == tenant_id, ActorIdentity.actor_id.in_(actor_ids),
                )
            )
        ).all():
            actor_to_principals[row.actor_id].add(row.principal_id)

    return {
        node_id: actor_to_principals.get(node_to_actor[node_id], {node_id}) if node_id in node_to_actor else {node_id}
        for node_id in node_ids
    }


async def open_credential_finding_counts_for_nodes(
    db: AsyncSession, tenant_id: uuid.UUID, node_ids: list[str],
) -> dict[str, int]:
    """Bulk, Actor-aware version of "how many open tier='credential'
    findings touch this principal" — the graph's node-badge query (Phase
    36f/37b). See _actor_sibling_principals_for_nodes for the identity-
    resolution mechanism this is built on. Three queries total regardless
    of len(node_ids), not N+1."""
    if not node_ids:
        return {}

    siblings_by_node = await _actor_sibling_principals_for_nodes(db, tenant_id, node_ids)
    all_principals = set(node_ids) | {p for principals in siblings_by_node.values() for p in principals}
    principal_counts: dict[str, int] = dict(
        (row.resource_uid, row.count)
        for row in (
            await db.execute(
                select(Finding.resource_uid, func.count(Finding.id).label("count")).where(
                    Finding.tenant_id == tenant_id, Finding.tier == "credential", Finding.status == "open",
                    Finding.resource_uid.in_(all_principals),
                ).group_by(Finding.resource_uid)
            )
        ).all()
    )

    return {
        node_id: sum(principal_counts.get(p, 0) for p in siblings_by_node.get(node_id, {node_id}))
        for node_id in node_ids
    }


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


async def open_policy_risk_finding_summaries_for_nodes(
    db: AsyncSession, tenant_id: uuid.UUID, node_ids: list[str],
) -> dict[str, dict]:
    """Same Actor-aware matching as open_credential_finding_counts_for_
    nodes, narrowed to the subset of tier='credential' findings that come
    from Cloudsplaining's DataExfiltration/ResourceExposure/ServiceWildcard/
    CredentialsExposure categories (check_id prefixed "cloudsplaining_",
    set in cloud_scan_service.py's _policy_risk_finding_candidates) —
    real "can act catastrophically without ever escalating privileges"
    risk, as distinct from routine password/MFA/access-key hygiene
    findings that also live under tier='credential'. Returns both a count
    and the worst severity per node, since a bare count can't distinguish
    a single critical finding from a pile of low ones. Severity is ranked
    in Python (_SEVERITY_RANK), not SQL string ordering — "critical" <
    "high" < "low" < "medium" alphabetically, which is not the real order."""
    if not node_ids:
        return {}

    siblings_by_node = await _actor_sibling_principals_for_nodes(db, tenant_id, node_ids)
    all_principals = set(node_ids) | {p for principals in siblings_by_node.values() for p in principals}
    rows = (
        await db.execute(
            select(Finding.resource_uid, Finding.severity).where(
                Finding.tenant_id == tenant_id, Finding.status == "open",
                Finding.check_id.like("cloudsplaining_%"),
                Finding.resource_uid.in_(all_principals),
            )
        )
    ).all()
    per_principal: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        per_principal[row.resource_uid].append(row.severity)

    summaries: dict[str, dict] = {}
    for node_id in node_ids:
        severities = [s for p in siblings_by_node.get(node_id, {node_id}) for s in per_principal.get(p, [])]
        worst = max(severities, key=lambda s: _SEVERITY_RANK.get(s, 0)) if severities else None
        summaries[node_id] = {"count": len(severities), "worst_severity": worst}
    return summaries
