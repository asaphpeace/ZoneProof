"""
Sentinel Command Tier 0 — cloud account connection lifecycle.
See BUILD_PLAN.md Phase 1 step 6 and ARCHITECTURE.md's CloudAccountConnection
spec. AWS-only for now; moto mocks STS/IAM so this exercises the real
boto3 assume-role call without touching a real AWS account.
"""
import json

import boto3
from httpx import AsyncClient
from moto import mock_aws
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_tenant, make_user


async def test_create_connection_returns_aws_setup(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/cloud-connections", json={"provider": "aws"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "pending_verification"
    assert body["external_id"]
    assert "AssumeRole" in body["trust_policy"]
    assert "SentinelCommandRole" in body["cloudformation_template"]
    assert len(body["instructions"]) == 3


async def test_create_connection_rejects_unsupported_provider(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/cloud-connections", json={"provider": "azure"})
    assert resp.status_code == 400


async def test_list_connections_scoped_to_tenant(auth_client):
    client, _tenant = auth_client
    await client.post("/cloud-connections", json={"provider": "aws"})
    resp = await client.get("/cloud-connections")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


async def test_verify_connection_succeeds_against_a_real_assumable_role(auth_client):
    # mock_aws as a decorator on an async def breaks pytest-asyncio's
    # coroutine detection (it wraps the function and pytest stops
    # recognizing it as async) — the context-manager form doesn't have
    # that problem.
    with mock_aws():
        client, _tenant = auth_client
        create_resp = await client.post("/cloud-connections", json={"provider": "aws"})
        connection = create_resp.json()
        external_id = connection["external_id"]

        # Create a role in the moto-mocked AWS account whose trust policy
        # matches what a real customer would deploy from our CloudFormation
        # template — same external_id condition, scoped to this test's
        # "calling" identity within moto's simulated account.
        iam = boto3.client("iam", region_name="us-east-1")
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }],
        }
        role = iam.create_role(
            RoleName="SentinelCommandReadOnly",
            AssumeRolePolicyDocument=json.dumps(trust_policy),
        )
        role_arn = role["Role"]["Arn"]

        resp = await client.post(f"/cloud-connections/{connection['id']}/verify", json={"role_arn": role_arn})
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "connected"
        assert body["role_arn"] == role_arn
        assert body["connected_at"] is not None


async def test_list_connections_surfaces_engagement_status(auth_client, db_session):
    """Same real bug as HostConnectionOut — a cloud connection can be
    "connected" while its own Engagement is still stuck at draft, and the
    frontend had no way to distinguish that from a fully scan-ready
    connection (see CoverageView.vue's cloudEngagementActive bug, which
    checked ANY tier's engagement instead of this connection's own)."""
    with mock_aws():
        client, _tenant = auth_client
        create_resp = await client.post("/cloud-connections", json={"provider": "aws"})
        connection = create_resp.json()
        external_id = connection["external_id"]

        iam = boto3.client("iam", region_name="us-east-1")
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }],
        }
        role = iam.create_role(RoleName="SentinelCommandReadOnly", AssumeRolePolicyDocument=json.dumps(trust_policy))
        role_arn = role["Role"]["Arn"]
        await client.post(f"/cloud-connections/{connection['id']}/verify", json={"role_arn": role_arn})

        resp = await client.post("/engagements", json={"tier": "cloud", "cloud_account_connection_ids": [connection["id"]]})
        engagement = resp.json()

        list_resp = await client.get("/cloud-connections")
        body = list_resp.json()[0]
        assert body["engagement_id"] == engagement["id"]
        assert body["engagement_status"] == "draft"

        from app.models import Engagement
        eng_row = await db_session.get(Engagement, engagement["id"])
        eng_row.status = "active"
        await db_session.commit()

        list_resp = await client.get("/cloud-connections")
        assert list_resp.json()[0]["engagement_status"] == "active"


async def test_verify_connection_fails_for_nonexistent_role(auth_client, monkeypatch):
    # moto's assume_role doesn't actually validate that the target role
    # exists or that its trust policy matches (it'll happily hand back
    # credentials for an ARN nothing ever created) — real AWS STS returns
    # AccessDenied in that case. Rather than rely on moto's fidelity here,
    # force the real failure mode (a botocore ClientError) directly and
    # verify our own error handling: status flips to 'error', request
    # returns 400, no credential or exception leaks out.
    from botocore.exceptions import ClientError

    def _raise(*args, **kwargs):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "AssumeRole")

    class _FakeSTS:
        assume_role = staticmethod(_raise)

    monkeypatch.setattr("app.services.cloud_scan_service.boto3.client", lambda *a, **k: _FakeSTS())

    client, _tenant = auth_client
    create_resp = await client.post("/cloud-connections", json={"provider": "aws"})
    connection = create_resp.json()

    fake_arn = "arn:aws:iam::123456789012:role/DoesNotExist"
    resp = await client.post(f"/cloud-connections/{connection['id']}/verify", json={"role_arn": fake_arn})
    assert resp.status_code == 400

    list_resp = await client.get("/cloud-connections")
    assert list_resp.json()[0]["status"] == "error"


async def test_verify_connection_handles_no_credentials_gracefully(auth_client, monkeypatch):
    """
    Regression test: found by exercising the real /verify endpoint against
    the live dev backend (no AWS credentials configured on that host) while
    building the Settings UI. NoCredentialsError is a BotoCoreError, not a
    ClientError -- the original except clause only caught ClientError, so
    this was propagating as an unhandled 500 instead of a graceful 400. The
    existing mocked test above never exercised this path since it only
    simulates ClientError, not the client-side "never reached AWS at all"
    failure mode.
    """
    from botocore.exceptions import NoCredentialsError

    def _raise(*args, **kwargs):
        raise NoCredentialsError()

    class _FakeSTS:
        assume_role = staticmethod(_raise)

    monkeypatch.setattr("app.services.cloud_scan_service.boto3.client", lambda *a, **k: _FakeSTS())

    client, _tenant = auth_client
    create_resp = await client.post("/cloud-connections", json={"provider": "aws"})
    connection = create_resp.json()

    resp = await client.post(
        f"/cloud-connections/{connection['id']}/verify",
        json={"role_arn": "arn:aws:iam::123456789012:role/Whatever"},
    )
    assert resp.status_code == 400

    list_resp = await client.get("/cloud-connections")
    assert list_resp.json()[0]["status"] == "error"


async def test_rescan_now_rejects_unconnected_connection(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/cloud-connections", json={"provider": "aws"})
    connection = create_resp.json()

    resp = await client.post(f"/cloud-connections/{connection['id']}/rescan")
    assert resp.status_code == 400


async def test_rescan_now_rejects_connection_with_no_engagement(auth_client, monkeypatch):
    # Verify the connection (status -> connected) without also creating an
    # engagement — rescan-now must refuse rather than scan with no
    # authorization on file, same consent-gate rule as the scheduler.
    with mock_aws():
        client, _tenant = auth_client
        create_resp = await client.post("/cloud-connections", json={"provider": "aws"})
        connection = create_resp.json()
        external_id = connection["external_id"]

        iam = boto3.client("iam", region_name="us-east-1")
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }],
        }
        role = iam.create_role(RoleName="SentinelCommandReadOnly", AssumeRolePolicyDocument=json.dumps(trust_policy))
        await client.post(f"/cloud-connections/{connection['id']}/verify", json={"role_arn": role["Role"]["Arn"]})

        resp = await client.post(f"/cloud-connections/{connection['id']}/rescan")
        assert resp.status_code == 400


async def test_rescan_now_triggers_rescan_connection_when_active(auth_client, monkeypatch):
    calls = []

    async def _fake_rescan(db, engagement, connection):
        calls.append((engagement.id, connection.id))

    monkeypatch.setattr("app.routers.cloud.cloud_scan_service.rescan_connection", _fake_rescan)

    with mock_aws():
        client, _tenant = auth_client
        create_resp = await client.post("/cloud-connections", json={"provider": "aws"})
        connection = create_resp.json()
        external_id = connection["external_id"]

        iam = boto3.client("iam", region_name="us-east-1")
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }],
        }
        role = iam.create_role(RoleName="SentinelCommandReadOnly", AssumeRolePolicyDocument=json.dumps(trust_policy))
        await client.post(f"/cloud-connections/{connection['id']}/verify", json={"role_arn": role["Role"]["Arn"]})

        engagement_resp = await client.post(
            "/engagements", json={"tier": "cloud", "cloud_account_connection_ids": [connection["id"]]}
        )
        engagement_id = engagement_resp.json()["id"]
        await client.post(f"/engagements/{engagement_id}/approve")

        resp = await client.post(f"/cloud-connections/{connection['id']}/rescan")
        assert resp.status_code == 200
        assert len(calls) == 1


async def test_connections_are_isolated_by_tenant(auth_client, client: AsyncClient, db_session: AsyncSession):
    owner_client, _owner_tenant = auth_client
    create_resp = await owner_client.post("/cloud-connections", json={"provider": "aws"})
    connection_id = create_resp.json()["id"]

    # A second, real user in a *different* tenant must not see or be able
    # to act on the first tenant's connection.
    other_tenant = await make_tenant(db_session, name="Other Workspace")
    await make_user(db_session, other_tenant, email="other@example.com", password="pass123")
    await db_session.flush()
    login = await client.post(
        "/auth/token",
        data={"username": "other@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    other_client = client
    other_client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    list_resp = await other_client.get("/cloud-connections")
    assert list_resp.json() == []

    verify_resp = await other_client.post(
        f"/cloud-connections/{connection_id}/verify", json={"role_arn": "arn:aws:iam::123456789012:role/X"}
    )
    assert verify_resp.status_code == 404


# ── PATCH /cloud-connections/{id} — display_name ────────────────────────────

async def test_rename_cloud_connection_sets_and_clears_display_name(auth_client):
    """display_name is the one piece of "environment" identity nothing in
    the AWS API can supply on its own (role_arn/account_id are real, stable
    technical facts, but not "Production" vs "Staging") — a human judgment
    call, so it needs its own editable field."""
    client, _tenant = auth_client
    create_resp = await client.post("/cloud-connections", json={"provider": "aws"})
    connection_id = create_resp.json()["id"]

    resp = await client.patch(f"/cloud-connections/{connection_id}", json={"display_name": "Client X — Production"})
    assert resp.status_code == 200
    assert resp.json()["display_name"] == "Client X — Production"

    resp = await client.patch(f"/cloud-connections/{connection_id}", json={"display_name": None})
    assert resp.status_code == 200
    assert resp.json()["display_name"] is None


async def test_rename_cloud_connection_is_audit_logged(auth_client, db_session):
    client, tenant = auth_client
    create_resp = await client.post("/cloud-connections", json={"provider": "aws"})
    connection_id = create_resp.json()["id"]

    await client.patch(f"/cloud-connections/{connection_id}", json={"display_name": "Client X — Production"})

    from sqlalchemy import select
    from app.models.audit_log import AuditLogEntry
    result = await db_session.execute(
        select(AuditLogEntry).where(AuditLogEntry.tenant_id == tenant.id, AuditLogEntry.action == "cloud_connection.renamed")
    )
    entry = result.scalars().one()
    assert entry.before == {"display_name": None}
    assert entry.after == {"display_name": "Client X — Production"}


async def test_rename_cloud_connection_requires_auth(client):
    resp = await client.patch("/cloud-connections/some-id", json={"display_name": "x"})
    assert resp.status_code == 401
