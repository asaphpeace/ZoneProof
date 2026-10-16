"""
Direct tests for the shared reconciliation helper backing every state-based
scan pass (Prowler, Inspector, Lynis, Exposure) — see the module's own
docstring for the real bug this fixes and why event-shaped tiers
(oauth_risk/phishing/impersonation/threat) deliberately don't use it.
"""
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CloudAccountConnection, CloudAsset, Engagement, Finding
from app.services.finding_reconciliation import reconcile_findings
from tests.factories import make_tenant


async def _make_engagement(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add(engagement)
    await db_session.flush()
    return tenant, engagement


async def _make_cloud_asset(db_session: AsyncSession, tenant, engagement):
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-1",
        status="connected", engagement_id=engagement.id,
    )
    asset = CloudAsset(
        id=uuid.uuid4(), tenant_id=tenant.id, cloud_account_connection_id=connection.id,
        resource_type="ec2_instance", resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-real",
    )
    db_session.add_all([connection, asset])
    await db_session.flush()
    return asset


def _candidate(tenant, engagement, check_id, resource_uid="r1", tier="cloud"):
    return Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier=tier, severity="high", title=check_id, status="open",
        check_id=check_id, resource_uid=resource_uid,
    )


async def test_new_candidate_gets_inserted(db_session: AsyncSession):
    tenant, engagement = await _make_engagement(db_session)
    candidate = _candidate(tenant, engagement, "check-a")

    inserted = await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[candidate], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    assert inserted == [candidate]
    all_rows = (await db_session.execute(select(Finding).where(Finding.engagement_id == engagement.id))).scalars().all()
    assert len(all_rows) == 1


async def test_matching_candidate_is_not_reinserted(db_session: AsyncSession):
    tenant, engagement = await _make_engagement(db_session)
    first_pass = await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[_candidate(tenant, engagement, "check-a")], key_fn=lambda f: (f.check_id, f.resource_uid),
    )
    assert len(first_pass) == 1

    second_pass = await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[_candidate(tenant, engagement, "check-a")], key_fn=lambda f: (f.check_id, f.resource_uid),
    )
    assert second_pass == []
    all_rows = (await db_session.execute(select(Finding).where(Finding.engagement_id == engagement.id))).scalars().all()
    assert len(all_rows) == 1
    assert all_rows[0].status == "open"


async def test_missing_candidate_marks_existing_remediated(db_session: AsyncSession):
    tenant, engagement = await _make_engagement(db_session)
    await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[_candidate(tenant, engagement, "check-a")], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    result = await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[], key_fn=lambda f: (f.check_id, f.resource_uid),
    )
    assert result == []
    all_rows = (await db_session.execute(select(Finding).where(Finding.engagement_id == engagement.id))).scalars().all()
    assert len(all_rows) == 1
    assert all_rows[0].status == "remediated"


async def test_same_check_id_different_resource_uid_are_distinct(db_session: AsyncSession):
    tenant, engagement = await _make_engagement(db_session)
    candidates = [
        _candidate(tenant, engagement, "check-a", resource_uid="region-us-east-1"),
        _candidate(tenant, engagement, "check-a", resource_uid="region-eu-west-1"),
    ]

    inserted = await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=candidates, key_fn=lambda f: (f.check_id, f.resource_uid),
    )
    assert len(inserted) == 2


async def test_matching_candidate_backfills_asset_id_on_existing_row(db_session: AsyncSession):
    """Real bug found live: a Finding first created before its CloudAsset
    existed yet (resource inventory added later than the check itself, or
    simply ran after this finding on its very first scan) kept
    asset_id=None forever — a matched existing row was never revisited on
    later scans, so a genuinely critical EC2-exposed-to-internet finding
    stayed invisible in the Resource Explorer's asset_id-only finding
    badge even after the real CloudAsset for that instance existed."""
    tenant, engagement = await _make_engagement(db_session)
    asset = await _make_cloud_asset(db_session, tenant, engagement)
    stale = _candidate(tenant, engagement, "check-a")
    stale.asset_id = None
    await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[stale], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    enriched_candidate = _candidate(tenant, engagement, "check-a")
    enriched_candidate.asset_id = asset.id
    second_pass = await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[enriched_candidate], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    assert second_pass == []  # still not re-inserted — same real issue, not a new one
    all_rows = (await db_session.execute(select(Finding).where(Finding.engagement_id == engagement.id))).scalars().all()
    assert len(all_rows) == 1
    assert all_rows[0].asset_id == asset.id  # backfilled, not left at None forever
    assert all_rows[0].status == "open"  # only asset_id changed, nothing else


async def test_matching_candidate_never_erases_a_resolved_asset_id(db_session: AsyncSession):
    """The reverse direction must never regress: once a real asset_id is
    on file, a candidate that (for whatever reason) resolves none this
    pass must not blank it back out."""
    tenant, engagement = await _make_engagement(db_session)
    asset = await _make_cloud_asset(db_session, tenant, engagement)
    first = _candidate(tenant, engagement, "check-a")
    first.asset_id = asset.id
    await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[first], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    unresolved = _candidate(tenant, engagement, "check-a")
    unresolved.asset_id = None
    await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[unresolved], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    all_rows = (await db_session.execute(select(Finding).where(Finding.engagement_id == engagement.id))).scalars().all()
    assert all_rows[0].asset_id == asset.id


async def test_matching_candidate_refreshes_extra_on_existing_row(db_session: AsyncSession):
    """Same real bug as asset_id, found live again: a matched existing row
    never got its extra re-synced from a later scan, so every enrichment
    field added after a Finding's first discovery (Prowler's compliance/
    categories/resource_metadata, Cloudsplaining's policy_document, etc.)
    silently stayed at whatever (or nothing) it was created with —
    confirmed against the real, exact SSH-exposed-to-internet finding this
    file's own asset_id test above is modeled on, still extra=None weeks
    after that enrichment code shipped."""
    tenant, engagement = await _make_engagement(db_session)
    stale = _candidate(tenant, engagement, "check-a")
    stale.extra = None
    await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[stale], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    enriched_candidate = _candidate(tenant, engagement, "check-a")
    enriched_candidate.extra = {"resource_metadata": {"port": 22, "cidr": "0.0.0.0/0"}}
    second_pass = await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[enriched_candidate], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    assert second_pass == []  # still not re-inserted — same real issue, not a new one
    all_rows = (await db_session.execute(select(Finding).where(Finding.engagement_id == engagement.id))).scalars().all()
    assert len(all_rows) == 1
    assert all_rows[0].extra == {"resource_metadata": {"port": 22, "cidr": "0.0.0.0/0"}}
    assert all_rows[0].status == "open"  # only extra changed, nothing else


async def test_matching_candidate_with_no_new_extra_leaves_existing_extra_alone(db_session: AsyncSession):
    """The reverse direction must never regress: a scan pass that has
    nothing new to add (candidate.extra is None — e.g. a real OCSF file
    that failed to parse this one time) must not blank out real data a
    prior scan already stored."""
    tenant, engagement = await _make_engagement(db_session)
    first = _candidate(tenant, engagement, "check-a")
    first.extra = {"resource_metadata": {"port": 22}}
    await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[first], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    unenriched = _candidate(tenant, engagement, "check-a")
    unenriched.extra = None
    await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[unenriched], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    all_rows = (await db_session.execute(select(Finding).where(Finding.engagement_id == engagement.id))).scalars().all()
    assert all_rows[0].extra == {"resource_metadata": {"port": 22}}


async def test_matching_candidate_refreshes_exploitability_on_existing_row(db_session: AsyncSession):
    """Same fix as extra above, applied pre-emptively to the new
    exploitability_service.py fields — a scoring-formula improvement must
    reach already-existing findings on the next rescan, not just brand-new
    ones, or this codebase would reintroduce the exact bug it just found
    and fixed live for extra."""
    tenant, engagement = await _make_engagement(db_session)
    stale = _candidate(tenant, engagement, "check-a")
    stale.exploitability = None
    await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[stale], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    scored_candidate = _candidate(tenant, engagement, "check-a")
    scored_candidate.exploitability = {"score": 30, "verdict": "urgent", "grade": "F", "explanation": "test"}
    second_pass = await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[scored_candidate], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    assert second_pass == []  # still not re-inserted — same real issue, not a new one
    all_rows = (await db_session.execute(select(Finding).where(Finding.engagement_id == engagement.id))).scalars().all()
    assert len(all_rows) == 1
    assert all_rows[0].exploitability == {"score": 30, "verdict": "urgent", "grade": "F", "explanation": "test"}
    assert all_rows[0].status == "open"  # only exploitability changed, nothing else


async def test_matching_candidate_with_no_new_exploitability_leaves_existing_score_alone(db_session: AsyncSession):
    """The reverse direction must never regress: a candidate with nothing
    new to add (exploitability is None) must not blank out a real score a
    prior scan already computed."""
    tenant, engagement = await _make_engagement(db_session)
    first = _candidate(tenant, engagement, "check-a")
    first.exploitability = {"score": 55, "verdict": "elevated", "grade": "D", "explanation": "test"}
    await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[first], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    unscored = _candidate(tenant, engagement, "check-a")
    unscored.exploitability = None
    await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[unscored], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    all_rows = (await db_session.execute(select(Finding).where(Finding.engagement_id == engagement.id))).scalars().all()
    assert all_rows[0].exploitability == {"score": 55, "verdict": "elevated", "grade": "D", "explanation": "test"}


async def test_scope_prevents_touching_findings_outside_it(db_session: AsyncSession):
    tenant, engagement = await _make_engagement(db_session)
    other_tier_finding = Finding(
        id=uuid.uuid4(), tenant_id=tenant.id, engagement_id=engagement.id,
        tier="host", severity="high", title="host finding", status="open",
        check_id="check-a", resource_uid="r1",
    )
    db_session.add(other_tier_finding)
    await db_session.commit()

    # Reconciling tier="cloud" with zero candidates must not touch the
    # tier="host" row sharing the same check_id/resource_uid.
    await reconcile_findings(
        db_session, engagement_id=engagement.id, scope=[Finding.tier == "cloud"],
        candidates=[], key_fn=lambda f: (f.check_id, f.resource_uid),
    )

    await db_session.refresh(other_tier_finding)
    assert other_tier_finding.status == "open"
