"""
Recurring rescan scheduler (BUILD_PLAN.md Phase 1 step 9). Building this
exposed a real gap: CloudAccountConnection and Engagement were designed to
reference each other (ARCHITECTURE.md's Engagement.scope.cloud_account_
connection_ids) but the relationship was never actually wired. Added a
direct engagement_id FK instead of matching against the JSONB scope list --
simpler, and it's what the scheduler needs to query against directly.
"""
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CloudAccountConnection, Engagement
from app.services import cloud_scan_service
from tests.factories import make_tenant


@pytest.fixture(autouse=True)
def _no_real_resource_inventory_sync(monkeypatch):
    # Phase 38: resource discovery now runs first in rescan_connection()'s
    # pass sequence — mocked here to a clean "found nothing" result so
    # every test in this file stays fast/offline/deterministic, matching
    # this file's existing discipline for the other 4 passes. Tests that
    # care about this pass specifically live in
    # tests/test_resource_inventory_service.py instead.
    async def _clean(db, conn, error_detail=None):
        return 0
    monkeypatch.setattr(cloud_scan_service, "run_resource_inventory_sync", _clean)


async def _make_connection(db_session: AsyncSession, tenant, *, status="connected", engagement=None):
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123",
        status=status, engagement_id=engagement.id if engagement else None,
    )
    db_session.add(connection)
    await db_session.flush()
    return connection


async def _make_engagement(db_session: AsyncSession, tenant, *, status="active"):
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status=status)
    db_session.add(engagement)
    await db_session.flush()
    return engagement


# ── Engagement creation links connections ─────────────────────────────────────

async def test_create_engagement_links_specified_connections(auth_client, db_session: AsyncSession):
    client, tenant = auth_client
    connection = await _make_connection(db_session, tenant, status="connected")
    await db_session.commit()

    resp = await client.post("/engagements", json={
        "tier": "cloud",
        "cloud_account_connection_ids": [str(connection.id)],
    })
    assert resp.status_code == 200
    engagement_id = resp.json()["id"]

    await db_session.refresh(connection)
    assert str(connection.engagement_id) == engagement_id


async def test_create_engagement_rejects_unknown_connection_id(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/engagements", json={
        "tier": "cloud",
        "cloud_account_connection_ids": [str(uuid.uuid4())],
    })
    assert resp.status_code == 400


async def test_create_engagement_rejects_another_tenants_connection(auth_client, db_session: AsyncSession):
    client, _tenant = auth_client
    other_tenant = await make_tenant(db_session, name="Other Workspace")
    other_connection = await _make_connection(db_session, other_tenant, status="connected")
    await db_session.commit()

    resp = await client.post("/engagements", json={
        "tier": "cloud",
        "cloud_account_connection_ids": [str(other_connection.id)],
    })
    assert resp.status_code == 400


# ── Scheduler batch logic ─────────────────────────────────────────────────────

async def test_rescan_all_due_connections_only_picks_connected_and_active_pairs(
    db_session: AsyncSession, monkeypatch
):
    tenant = await make_tenant(db_session)

    active_engagement = await _make_engagement(db_session, tenant, status="active")
    due = await _make_connection(db_session, tenant, status="connected", engagement=active_engagement)

    revoked_engagement = await _make_engagement(db_session, tenant, status="revoked")
    await _make_connection(db_session, tenant, status="connected", engagement=revoked_engagement)

    unlinked = await _make_connection(db_session, tenant, status="connected", engagement=None)

    error_connection = await _make_connection(db_session, tenant, status="error", engagement=active_engagement)

    await db_session.commit()

    scanned_connection_ids = []

    async def _fake_rescan(db, engagement, connection):
        scanned_connection_ids.append(connection.id)

    monkeypatch.setattr(cloud_scan_service, "rescan_connection", _fake_rescan)

    count = await cloud_scan_service.rescan_all_due_connections(db_session)

    assert count == 1
    assert scanned_connection_ids == [due.id]
    assert unlinked.id not in scanned_connection_ids
    assert error_connection.id not in scanned_connection_ids


async def test_rescan_all_due_connections_continues_after_one_failure(db_session: AsyncSession, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant, status="active")
    failing = await _make_connection(db_session, tenant, status="connected", engagement=engagement)
    healthy = await _make_connection(db_session, tenant, status="connected", engagement=engagement)
    await db_session.commit()

    scanned = []

    async def _fake_rescan(db, eng, connection):
        if connection.id == failing.id:
            raise RuntimeError("boom")
        scanned.append(connection.id)

    monkeypatch.setattr(cloud_scan_service, "rescan_connection", _fake_rescan)

    count = await cloud_scan_service.rescan_all_due_connections(db_session)

    assert count == 2  # both were attempted
    assert scanned == [healthy.id]  # only the non-failing one actually completed


# ── Per-action safety check inside rescan_connection itself ───────────────────

async def test_rescan_connection_skips_entirely_if_engagement_not_active(db_session: AsyncSession, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant, status="revoked")
    connection = await _make_connection(db_session, tenant, status="connected", engagement=engagement)
    await db_session.commit()

    called = []
    monkeypatch.setattr(cloud_scan_service, "run_prowler_scan", lambda *a: called.append("prowler"))
    monkeypatch.setattr(cloud_scan_service, "run_priv_esc_analysis", lambda *a: called.append("privesc"))

    await cloud_scan_service.rescan_connection(db_session, engagement, connection)

    assert called == []


async def test_rescan_connection_stops_before_prowler_pass_if_revoked_during_resource_discovery(
    db_session: AsyncSession, monkeypatch
):
    # Phase 38: resource discovery is the real first pass now — same
    # mid-scan revoke check every other pass boundary already gets.
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant, status="active")
    connection = await _make_connection(db_session, tenant, status="connected", engagement=engagement)
    await db_session.commit()

    async def _revoke_during_resources(db, conn, error_detail=None):
        eng = await db.get(Engagement, engagement.id)
        eng.status = "revoked"
        await db.commit()
        return 0

    prowler_called = []

    async def _fake_prowler(db, eng, conn, error_detail=None):
        prowler_called.append(True)
        return []

    monkeypatch.setattr(cloud_scan_service, "run_resource_inventory_sync", _revoke_during_resources)
    monkeypatch.setattr(cloud_scan_service, "run_prowler_scan", _fake_prowler)

    await cloud_scan_service.rescan_connection(db_session, engagement, connection)

    assert prowler_called == []  # never reached — resources itself already tripped the revoke check


async def test_rescan_connection_stops_before_cloudsplaining_pass_if_revoked_during_prowler(
    db_session: AsyncSession, monkeypatch
):
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant, status="active")
    connection = await _make_connection(db_session, tenant, status="connected", engagement=engagement)
    await db_session.commit()

    async def _revoke_during_prowler(db, eng, conn, error_detail=None):
        # Simulate someone hitting the revoke endpoint while Prowler's
        # subprocess is still running.
        eng.status = "revoked"
        await db.commit()
        return []

    privesc_called = []

    async def _fake_privesc(db, eng, conn, error_detail=None):
        privesc_called.append(True)
        return []

    monkeypatch.setattr(cloud_scan_service, "run_prowler_scan", _revoke_during_prowler)
    monkeypatch.setattr(cloud_scan_service, "run_priv_esc_analysis", _fake_privesc)

    await cloud_scan_service.rescan_connection(db_session, engagement, connection)

    assert privesc_called == []  # never reached — the mid-scan status check caught it


async def test_rescan_connection_stops_before_inspector_pass_if_revoked_during_cloudsplaining(
    db_session: AsyncSession, monkeypatch
):
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant, status="active")
    connection = await _make_connection(db_session, tenant, status="connected", engagement=engagement)
    await db_session.commit()

    async def _noop_prowler(db, eng, conn, error_detail=None):
        return []

    async def _revoke_during_privesc(db, eng, conn, error_detail=None):
        eng.status = "revoked"
        await db.commit()
        return []

    inspector_called = []

    async def _fake_inspector(db, eng, conn, error_detail=None):
        inspector_called.append(True)
        return []

    monkeypatch.setattr(cloud_scan_service, "run_prowler_scan", _noop_prowler)
    monkeypatch.setattr(cloud_scan_service, "run_priv_esc_analysis", _revoke_during_privesc)
    monkeypatch.setattr(cloud_scan_service, "run_inspector_scan", _fake_inspector)

    await cloud_scan_service.rescan_connection(db_session, engagement, connection)

    assert inspector_called == []  # never reached — same mid-scan check, third checkpoint


async def test_rescan_connection_stops_before_credential_pass_if_revoked_during_inspector(
    db_session: AsyncSession, monkeypatch
):
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant, status="active")
    connection = await _make_connection(db_session, tenant, status="connected", engagement=engagement)
    await db_session.commit()

    async def _noop(db, eng, conn, error_detail=None):
        return []

    async def _revoke_during_inspector(db, eng, conn, error_detail=None):
        eng.status = "revoked"
        await db.commit()
        return []

    credential_called = []

    async def _fake_credential(db, eng, conn, error_detail=None):
        credential_called.append(True)
        return []

    monkeypatch.setattr(cloud_scan_service, "run_prowler_scan", _noop)
    monkeypatch.setattr(cloud_scan_service, "run_priv_esc_analysis", _noop)
    monkeypatch.setattr(cloud_scan_service, "run_inspector_scan", _revoke_during_inspector)
    monkeypatch.setattr(cloud_scan_service, "run_credential_hygiene_scan", _fake_credential)

    await cloud_scan_service.rescan_connection(db_session, engagement, connection)

    assert credential_called == []  # never reached — same mid-scan check, fourth checkpoint


async def test_rescan_connection_does_not_mark_failed_when_only_inspector_is_not_enabled(
    db_session: AsyncSession, monkeypatch,
):
    """Coverage Map plan Phase 8: every brand-new AWS account has Inspector2
    opted out by default — that alone must not flip the whole connection to
    'failed' when Prowler/Cloudsplaining/credential hygiene all genuinely
    succeeded, the exact day-one-every-customer-sees-red gap this closes."""
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant, status="active")
    connection = await _make_connection(db_session, tenant, status="connected", engagement=engagement)
    await db_session.commit()

    async def _clean(db, eng, conn, error_detail=None):
        return []

    async def _inspector_not_enabled(db, eng, conn, error_detail=None):
        if error_detail is not None:
            error_detail["message"] = "Amazon Inspector2 is not enabled on this AWS account"
            error_detail["not_enabled"] = True
        return None

    monkeypatch.setattr(cloud_scan_service, "run_prowler_scan", _clean)
    monkeypatch.setattr(cloud_scan_service, "run_priv_esc_analysis", _clean)
    monkeypatch.setattr(cloud_scan_service, "run_inspector_scan", _inspector_not_enabled)
    monkeypatch.setattr(cloud_scan_service, "run_credential_hygiene_scan", _clean)

    await cloud_scan_service.rescan_connection(db_session, engagement, connection)

    assert connection.last_scan_status == "success"  # not "failed"
    assert connection.last_scan_results["inspector"]["status"] == "not_enabled"


# ── last_scan_status tracking — a failed pass must not look like a clean scan ──

async def test_rescan_connection_marks_success_when_every_pass_completes(db_session: AsyncSession, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant, status="active")
    connection = await _make_connection(db_session, tenant, status="connected", engagement=engagement)
    await db_session.commit()

    # A real clean scan: every pass completes and finds nothing (empty list,
    # not None) — this is the case that used to be indistinguishable from
    # "never ran."
    async def _clean(db, eng, conn, error_detail=None):
        return []

    monkeypatch.setattr(cloud_scan_service, "run_prowler_scan", _clean)
    monkeypatch.setattr(cloud_scan_service, "run_priv_esc_analysis", _clean)
    monkeypatch.setattr(cloud_scan_service, "run_inspector_scan", _clean)
    monkeypatch.setattr(cloud_scan_service, "run_credential_hygiene_scan", _clean)

    await cloud_scan_service.rescan_connection(db_session, engagement, connection)

    assert connection.last_scan_status == "success"
    assert connection.last_scan_error is None
    assert connection.last_scanned_at is not None
    assert connection.last_scan_results == {
        "resources": {"status": "success", "error": None},
        "prowler": {"status": "success", "error": None},
        "cloudsplaining": {"status": "success", "error": None},
        "inspector": {"status": "success", "error": None},
        "credential": {"status": "success", "error": None},
    }


async def test_rescan_connection_marks_failed_when_a_pass_returns_none(db_session: AsyncSession, monkeypatch):
    tenant = await make_tenant(db_session)
    engagement = await _make_engagement(db_session, tenant, status="active")
    connection = await _make_connection(db_session, tenant, status="connected", engagement=engagement)
    await db_session.commit()

    async def _clean(db, eng, conn, error_detail=None):
        return []

    async def _broken(db, eng, conn, error_detail=None):
        if error_detail is not None:
            error_detail["message"] = "Timed out after 900s"
        return None  # e.g. Prowler timed out or exited non-zero

    monkeypatch.setattr(cloud_scan_service, "run_prowler_scan", _broken)
    monkeypatch.setattr(cloud_scan_service, "run_priv_esc_analysis", _clean)
    monkeypatch.setattr(cloud_scan_service, "run_inspector_scan", _clean)
    monkeypatch.setattr(cloud_scan_service, "run_credential_hygiene_scan", _clean)

    await cloud_scan_service.rescan_connection(db_session, engagement, connection)

    assert connection.last_scan_status == "failed"
    assert "Prowler" in connection.last_scan_error

    # The per-pass breakdown is the actual feature — a customer must be
    # able to see that Cloudsplaining/Inspector succeeded even though the
    # aggregate says "failed", instead of the aggregate hiding which pass
    # actually broke (this was a real, reported gap: a customer couldn't
    # tell a working Prowler pass from a failed one behind one shared
    # "Inspector scan failed" string).
    assert connection.last_scan_results == {
        "resources": {"status": "success", "error": None},
        "prowler": {"status": "failed", "error": "Timed out after 900s"},
        "cloudsplaining": {"status": "success", "error": None},
        "inspector": {"status": "success", "error": None},
        "credential": {"status": "success", "error": None},
    }
