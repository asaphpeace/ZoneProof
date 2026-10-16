"""
Resource inventory sync (Phase 38a) — populates the long-dormant
CloudAsset table from the Resource Groups Tagging API (full inventory)
and a direct IAM listing. Direct boto3 mocking, matching
test_prowler_scan.py's own established house convention for this exact
kind of test (not moto — moto's resourcegroupstaggingapi coverage isn't
reliable enough to depend on).
"""
import uuid

from botocore.exceptions import ClientError
from sqlalchemy import select

from app.models import CloudAccountConnection, CloudAsset
from app.services import resource_inventory_service as svc
from tests.factories import make_tenant


class _FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class _FakeSTSClient:
    def assume_role(self, **kwargs):
        return {"Credentials": {"AccessKeyId": "AKIA", "SecretAccessKey": "secret", "SessionToken": "token"}}


class _FailingSTSClient:
    def assume_role(self, **kwargs):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "AssumeRole")


class _FakeEC2Client:
    def __init__(
        self, instances_by_region: dict | None = None, fail_describe_instances: bool = False,
        security_groups_by_region: dict | None = None, fail_describe_security_groups: bool = False,
    ):
        self._instances_by_region = instances_by_region or {}
        self._fail_describe_instances = fail_describe_instances
        self._security_groups_by_region = security_groups_by_region or {}
        self._fail_describe_security_groups = fail_describe_security_groups
        self._region = None

    def describe_regions(self, **kwargs):
        return {"Regions": [
            {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
            {"RegionName": "eu-north-1", "OptInStatus": "opted-in"},
        ]}

    def get_paginator(self, name):
        if name == "describe_instances":
            if self._fail_describe_instances:
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "DescribeInstances")
            reservations = self._instances_by_region.get(self._region, [])
            return _FakePaginator([{"Reservations": reservations}])
        if name == "describe_security_groups":
            if self._fail_describe_security_groups:
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "DescribeSecurityGroups")
            groups = self._security_groups_by_region.get(self._region, [])
            return _FakePaginator([{"SecurityGroups": groups}])
        raise AssertionError(f"unexpected paginator {name}")


class _FakeTaggingClient:
    def __init__(self, resources_by_region: dict):
        self._resources_by_region = resources_by_region
        self._region = None

    def get_paginator(self, name):
        assert name == "get_resources"
        mappings = self._resources_by_region.get(self._region, [])
        return _FakePaginator([{"ResourceTagMappingList": mappings}])


class _FlakyTaggingClient:
    def get_paginator(self, name):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "GetResources")


class _FakeIAMClient:
    def __init__(
        self, roles=None, users=None, groups=None, instance_profiles=None, fail_instance_profiles=False,
        simulate_responses=None, fail_simulate=False,
    ):
        self._roles = roles or []
        self._users = users or []
        self._groups = groups or []
        self._instance_profiles = instance_profiles or []
        self._fail_instance_profiles = fail_instance_profiles
        # {(principal_arn, bucket_arn): {"s3:GetObject", ...}} — the subset
        # of _S3_ACCESS_ACTIONS this fake reports as "allowed" for that pair.
        self._simulate_responses = simulate_responses or {}
        self._fail_simulate = fail_simulate
        self.simulate_call_count = 0

    def get_paginator(self, name):
        if name == "list_roles":
            return _FakePaginator([{"Roles": [{"Arn": a} for a in self._roles]}])
        if name == "list_users":
            return _FakePaginator([{"Users": [{"Arn": a} for a in self._users]}])
        if name == "list_groups":
            return _FakePaginator([{"Groups": [{"Arn": a} for a in self._groups]}])
        if name == "list_instance_profiles":
            if self._fail_instance_profiles:
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "ListInstanceProfiles")
            return _FakePaginator([{"InstanceProfiles": self._instance_profiles}])
        raise AssertionError(f"unexpected paginator {name}")

    def simulate_principal_policy(self, PolicySourceArn, ActionNames, ResourceArns):
        self.simulate_call_count += 1
        if self._fail_simulate:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "SimulatePrincipalPolicy")
        allowed = self._simulate_responses.get((PolicySourceArn, ResourceArns[0]), set())
        return {"EvaluationResults": [
            {"EvalActionName": a, "EvalDecision": "allowed" if a in allowed else "implicitDeny"}
            for a in ActionNames
        ]}


class _FakeS3Client:
    def __init__(self, buckets=None, tags_by_bucket=None, fail_list_buckets=False, fail_tagging_buckets=None):
        self._buckets = buckets or []
        self._tags_by_bucket = tags_by_bucket or {}
        self._fail_list_buckets = fail_list_buckets
        self._fail_tagging_buckets = fail_tagging_buckets or set()

    def list_buckets(self):
        if self._fail_list_buckets:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "ListBuckets")
        return {"Buckets": [{"Name": name} for name in self._buckets]}

    def get_bucket_tagging(self, Bucket):
        if Bucket in self._fail_tagging_buckets:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "GetBucketTagging")
        tags = self._tags_by_bucket.get(Bucket)
        if tags is None:
            raise ClientError({"Error": {"Code": "NoSuchTagSet", "Message": "no tags"}}, "GetBucketTagging")
        return {"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]}


class _FailingIAMClient:
    def get_paginator(self, name):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "ListRoles")


class _FakeSession:
    def __init__(self, tagging_client_factory, iam_client, ec2_client_factory=None, s3_client=None):
        self._tagging_client_factory = tagging_client_factory
        self._iam_client = iam_client
        self._ec2_client_factory = ec2_client_factory or (lambda: _FakeEC2Client())
        self._s3_client = s3_client or _FakeS3Client()

    def client(self, service, region_name=None, **kwargs):
        if service == "ec2":
            client = self._ec2_client_factory()
            client._region = region_name
            return client
        if service == "resourcegroupstaggingapi":
            client = self._tagging_client_factory()
            client._region = region_name
            return client
        if service == "iam":
            return self._iam_client
        if service == "s3":
            return self._s3_client
        raise AssertionError(f"unexpected service {service}")


class _FakeBoto3:
    def __init__(self, tagging_client_factory=None, iam_client=None, sts_client=None, ec2_client_factory=None, s3_client=None):
        self._tagging_client_factory = tagging_client_factory or (lambda: _FakeTaggingClient({}))
        self._iam_client = iam_client or _FakeIAMClient()
        self._sts_client = sts_client or _FakeSTSClient()
        self._ec2_client_factory = ec2_client_factory or (lambda: _FakeEC2Client())
        self._s3_client = s3_client or _FakeS3Client()

    def client(self, service, **kwargs):
        assert service == "sts"
        return self._sts_client

    def Session(self, **kwargs):
        return _FakeSession(self._tagging_client_factory, self._iam_client, self._ec2_client_factory, self._s3_client)


async def _make_connection(db_session) -> CloudAccountConnection:
    tenant = await make_tenant(db_session)
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123", status="connected",
    )
    db_session.add(connection)
    await db_session.flush()
    return connection


def test_resource_type_from_arn_prefers_the_resource_type_segment():
    assert svc._resource_type_from_arn("arn:aws:ec2:us-east-1:123:instance/i-abc") == "ec2_instance"
    assert svc._resource_type_from_arn("arn:aws:ec2:us-east-1:123:security-group/sg-abc") == "ec2_security_group"
    assert svc._resource_type_from_arn("arn:aws:iam::123:role/my-role") == "iam_role"


def test_resource_type_from_arn_s3_bucket_has_no_separate_type_segment():
    assert svc._resource_type_from_arn("arn:aws:s3:::my-bucket") == "s3_bucket"


def test_resource_type_from_arn_handles_non_arn_input():
    assert svc._resource_type_from_arn("not-an-arn") == "unknown"


async def test_run_resource_inventory_sync_upserts_tagging_api_resources(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    resources_by_region = {"eu-north-1": [{"ResourceARN": "arn:aws:ec2:eu-north-1:123:instance/i-abc", "Tags": [{"Key": "Name", "Value": "web-1"}]}]}
    fake_boto3 = _FakeBoto3(tagging_client_factory=lambda: _FakeTaggingClient(resources_by_region))
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    synced = await svc.run_resource_inventory_sync(db_session, connection)
    assert synced == 1

    asset = await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:ec2:eu-north-1:123:instance/i-abc"))
    assert asset is not None
    assert asset.resource_type == "ec2_instance"
    assert asset.region == "eu-north-1"
    assert asset.resource_metadata["tags"] == {"Name": "web-1"}


async def test_run_resource_inventory_sync_upserts_iam_principals(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    fake_boto3 = _FakeBoto3(iam_client=_FakeIAMClient(roles=["arn:aws:iam::123:role/deploy"], users=["arn:aws:iam::123:user/alice"]))
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    synced = await svc.run_resource_inventory_sync(db_session, connection)
    assert synced == 2

    role_asset = await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:iam::123:role/deploy"))
    assert role_asset.resource_type == "iam_role"
    user_asset = await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:iam::123:user/alice"))
    assert user_asset.resource_type == "iam_user"


async def test_run_resource_inventory_sync_updates_last_seen_on_resync_not_duplicate(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    fake_boto3 = _FakeBoto3(iam_client=_FakeIAMClient(users=["arn:aws:iam::123:user/alice"]))
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    await svc.run_resource_inventory_sync(db_session, connection)
    first_seen = (await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:iam::123:user/alice"))).first_seen_at

    await svc.run_resource_inventory_sync(db_session, connection)
    all_assets = (await db_session.execute(select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:iam::123:user/alice"))).scalars().all()
    assert len(all_assets) == 1  # updated in place, not duplicated
    assert all_assets[0].first_seen_at == first_seen


async def test_run_resource_inventory_sync_returns_none_on_assume_role_failure(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    fake_boto3 = _FakeBoto3(sts_client=_FailingSTSClient())
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    error_detail = {}
    result = await svc.run_resource_inventory_sync(db_session, connection, error_detail=error_detail)
    assert result is None
    assert error_detail["message"]


async def test_run_resource_inventory_sync_tolerates_a_flaky_tagging_region_and_still_syncs_iam(db_session, monkeypatch):
    # One region's tagging failure must not blank out IAM discovery, which
    # is a completely independent call.
    connection = await _make_connection(db_session)
    fake_boto3 = _FakeBoto3(
        tagging_client_factory=lambda: _FlakyTaggingClient(),
        iam_client=_FakeIAMClient(users=["arn:aws:iam::123:user/alice"]),
    )
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    synced = await svc.run_resource_inventory_sync(db_session, connection)
    assert synced == 1  # only the IAM user, tagging contributed nothing but didn't crash the pass


async def test_run_resource_inventory_sync_tolerates_a_failing_iam_listing(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    resources_by_region = {"eu-north-1": [{"ResourceARN": "arn:aws:s3:::my-bucket", "Tags": []}]}
    fake_boto3 = _FakeBoto3(
        tagging_client_factory=lambda: _FakeTaggingClient(resources_by_region),
        iam_client=_FailingIAMClient(),
    )
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    synced = await svc.run_resource_inventory_sync(db_session, connection)
    assert synced == 1  # only the S3 bucket, IAM listing failed but didn't crash the pass


# ── EC2 -> IAM role resolution (RUNS_AS edge's data source, graph_service.py) ──

async def test_run_resource_inventory_sync_resolves_ec2_role_via_instance_profile(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    resources_by_region = {
        "eu-north-1": [{"ResourceARN": "arn:aws:ec2:eu-north-1:123:instance/i-abc", "Tags": [{"Key": "Name", "Value": "web-1"}]}],
    }
    instances_by_region = {
        "eu-north-1": [{"Instances": [
            {"InstanceId": "i-abc", "IamInstanceProfile": {"Arn": "arn:aws:iam::123:instance-profile/web-profile"}},
        ]}],
    }
    fake_boto3 = _FakeBoto3(
        tagging_client_factory=lambda: _FakeTaggingClient(resources_by_region),
        ec2_client_factory=lambda: _FakeEC2Client(instances_by_region),
        iam_client=_FakeIAMClient(instance_profiles=[
            {"Arn": "arn:aws:iam::123:instance-profile/web-profile", "Roles": [{"Arn": "arn:aws:iam::123:role/web-role"}]},
        ]),
    )
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    await svc.run_resource_inventory_sync(db_session, connection)

    asset = await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:ec2:eu-north-1:123:instance/i-abc"))
    assert asset.resource_metadata["role_arn"] == "arn:aws:iam::123:role/web-role"
    assert asset.resource_metadata["tags"] == {"Name": "web-1"}  # merged, not clobbered


async def test_run_resource_inventory_sync_leaves_role_arn_absent_without_an_instance_profile(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    resources_by_region = {"eu-north-1": [{"ResourceARN": "arn:aws:ec2:eu-north-1:123:instance/i-noprofile", "Tags": []}]}
    instances_by_region = {"eu-north-1": [{"Instances": [{"InstanceId": "i-noprofile"}]}]}  # no IamInstanceProfile key
    fake_boto3 = _FakeBoto3(
        tagging_client_factory=lambda: _FakeTaggingClient(resources_by_region),
        ec2_client_factory=lambda: _FakeEC2Client(instances_by_region),
    )
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    await svc.run_resource_inventory_sync(db_session, connection)

    asset = await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:ec2:eu-north-1:123:instance/i-noprofile"))
    assert "role_arn" not in asset.resource_metadata  # an honest "no role" signal, not fabricated


async def test_run_resource_inventory_sync_leaves_role_arn_absent_when_profile_has_no_roles(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    resources_by_region = {"eu-north-1": [{"ResourceARN": "arn:aws:ec2:eu-north-1:123:instance/i-abc", "Tags": []}]}
    instances_by_region = {
        "eu-north-1": [{"Instances": [{"InstanceId": "i-abc", "IamInstanceProfile": {"Arn": "arn:aws:iam::123:instance-profile/empty"}}]}],
    }
    fake_boto3 = _FakeBoto3(
        tagging_client_factory=lambda: _FakeTaggingClient(resources_by_region),
        ec2_client_factory=lambda: _FakeEC2Client(instances_by_region),
        iam_client=_FakeIAMClient(instance_profiles=[{"Arn": "arn:aws:iam::123:instance-profile/empty", "Roles": []}]),
    )
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    await svc.run_resource_inventory_sync(db_session, connection)

    asset = await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:ec2:eu-north-1:123:instance/i-abc"))
    assert "role_arn" not in asset.resource_metadata


async def test_run_resource_inventory_sync_tolerates_failing_list_instance_profiles(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    resources_by_region = {"eu-north-1": [{"ResourceARN": "arn:aws:ec2:eu-north-1:123:instance/i-abc", "Tags": []}]}
    fake_boto3 = _FakeBoto3(
        tagging_client_factory=lambda: _FakeTaggingClient(resources_by_region),
        iam_client=_FakeIAMClient(fail_instance_profiles=True),
    )
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    synced = await svc.run_resource_inventory_sync(db_session, connection)
    assert synced == 1  # tagging API result still counted, role resolution just skipped

    asset = await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:ec2:eu-north-1:123:instance/i-abc"))
    assert "role_arn" not in asset.resource_metadata


async def test_run_resource_inventory_sync_tolerates_failing_describe_instances(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    resources_by_region = {"eu-north-1": [{"ResourceARN": "arn:aws:ec2:eu-north-1:123:instance/i-abc", "Tags": []}]}
    fake_boto3 = _FakeBoto3(
        tagging_client_factory=lambda: _FakeTaggingClient(resources_by_region),
        ec2_client_factory=lambda: _FakeEC2Client(fail_describe_instances=True),
        iam_client=_FakeIAMClient(instance_profiles=[
            {"Arn": "arn:aws:iam::123:instance-profile/web-profile", "Roles": [{"Arn": "arn:aws:iam::123:role/web-role"}]},
        ]),
    )
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    synced = await svc.run_resource_inventory_sync(db_session, connection)
    assert synced == 1  # a describe_instances failure in one region doesn't crash the whole pass

    asset = await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:ec2:eu-north-1:123:instance/i-abc"))
    assert "role_arn" not in asset.resource_metadata


# ── High-value heuristic default (_infer_high_value) ──────────────────────

def test_infer_high_value_true_for_a_data_bearing_resource_with_no_env_hint():
    assert svc._infer_high_value("s3_bucket", {"Name": "customer-uploads"}) is True
    assert svc._infer_high_value("rds_db_instance", {}) is True
    assert svc._infer_high_value("dynamodb_table", {"Owner": "platform-team"}) is True
    assert svc._infer_high_value("redshift_cluster", {}) is True


def test_infer_high_value_false_with_a_non_prod_tag():
    assert svc._infer_high_value("s3_bucket", {"Environment": "staging"}) is False
    assert svc._infer_high_value("rds_db_instance", {"Name": "orders-dev"}) is False
    assert svc._infer_high_value("dynamodb_table", {"env": "sandbox"}) is False


def test_infer_high_value_false_for_a_non_data_bearing_resource_type_regardless_of_tags():
    assert svc._infer_high_value("ec2_instance", {}) is False
    assert svc._infer_high_value("iam_role", {}) is False
    assert svc._infer_high_value("ec2_security_group", {"Environment": "production"}) is False


async def test_run_resource_inventory_sync_sets_the_heuristic_default_on_a_new_asset(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    resources_by_region = {"eu-north-1": [{"ResourceARN": "arn:aws:s3:::prod-customer-data", "Tags": []}]}
    fake_boto3 = _FakeBoto3(tagging_client_factory=lambda: _FakeTaggingClient(resources_by_region))
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    await svc.run_resource_inventory_sync(db_session, connection)

    asset = await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:s3:::prod-customer-data"))
    assert asset.is_high_value is True  # S3 bucket, no non-prod tag hint
    assert asset.high_value_set_by_user_id is None  # still heuristic, no manual override yet


async def test_run_resource_inventory_sync_never_overwrites_a_manual_high_value_override(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    resources_by_region = {"eu-north-1": [{"ResourceARN": "arn:aws:s3:::my-bucket", "Tags": []}]}
    fake_boto3 = _FakeBoto3(tagging_client_factory=lambda: _FakeTaggingClient(resources_by_region))
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    await svc.run_resource_inventory_sync(db_session, connection)
    asset = await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:s3:::my-bucket"))
    assert asset.is_high_value is True  # heuristic default for a clean S3 bucket

    # Customer manually overrides it to False (e.g. "this is just a public assets bucket").
    from datetime import datetime, timezone
    from tests.factories import make_user
    actor_tenant = await make_tenant(db_session)
    actor = await make_user(db_session, actor_tenant, email="override-actor@example.com")
    asset.is_high_value = False
    asset.high_value_set_by_user_id = actor.id
    asset.high_value_set_at = datetime.now(timezone.utc)
    await db_session.commit()

    # A later rescan sees the exact same real data and must not flip it back.
    await svc.run_resource_inventory_sync(db_session, connection)
    await db_session.refresh(asset)
    assert asset.is_high_value is False
    assert "role_arn" not in asset.resource_metadata


# ── Security group capture (LATERAL_MOVEMENT edge's data source) ──────────

async def test_run_resource_inventory_sync_creates_a_security_group_asset_from_scratch(db_session, monkeypatch):
    # Security groups aren't tagged in real accounts (confirmed this
    # session) — the tagging API sync above never discovers them, so this
    # is the only source and must CREATE the CloudAsset row, not just
    # enrich an existing one.
    connection = await _make_connection(db_session)
    security_groups_by_region = {"eu-north-1": [{
        "GroupId": "sg-abc", "GroupName": "web-sg", "VpcId": "vpc-1",
        "IpPermissions": [{
            "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
            "IpRanges": [], "UserIdGroupPairs": [{"GroupId": "sg-web"}],
        }],
        "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "UserIdGroupPairs": []}],
    }]}
    fake_boto3 = _FakeBoto3(ec2_client_factory=lambda: _FakeEC2Client(security_groups_by_region=security_groups_by_region))
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    await svc.run_resource_inventory_sync(db_session, connection)

    asset = await db_session.scalar(
        select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:ec2:eu-north-1:123456789012:security-group/sg-abc")
    )
    assert asset is not None
    assert asset.resource_type == "ec2_security_group"
    assert asset.resource_metadata["referenced_group_ids"] == ["sg-web"]
    assert asset.resource_metadata["ingress_rules"][0]["from_port"] == 5432
    assert asset.resource_metadata["egress_rules"][0]["protocol"] == "-1"


async def test_run_resource_inventory_sync_captures_ipv6_ranges_in_security_group_rules(db_session, monkeypatch):
    # EXPOSED_TO_INTERNET's own port-level check keys on this same cidrs
    # list looking for "::/0" alongside "0.0.0.0/0" — an IPv6-only rule
    # must not be silently invisible to it.
    connection = await _make_connection(db_session)
    security_groups_by_region = {"eu-north-1": [{
        "GroupId": "sg-v6", "GroupName": "v6-sg", "VpcId": "vpc-1",
        "IpPermissions": [{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}], "UserIdGroupPairs": [],
        }],
        "IpPermissionsEgress": [],
    }]}
    fake_boto3 = _FakeBoto3(ec2_client_factory=lambda: _FakeEC2Client(security_groups_by_region=security_groups_by_region))
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    await svc.run_resource_inventory_sync(db_session, connection)

    asset = await db_session.scalar(
        select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:ec2:eu-north-1:123456789012:security-group/sg-v6")
    )
    assert asset.resource_metadata["ingress_rules"][0]["cidrs"] == ["::/0"]


async def test_run_resource_inventory_sync_enriches_ec2_instances_with_security_group_ids(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    resources_by_region = {"eu-north-1": [{"ResourceARN": "arn:aws:ec2:eu-north-1:123456789012:instance/i-abc", "Tags": []}]}
    instances_by_region = {
        "eu-north-1": [{"Instances": [
            {"InstanceId": "i-abc", "SecurityGroups": [{"GroupId": "sg-web"}, {"GroupId": "sg-default"}]},
        ]}],
    }
    fake_boto3 = _FakeBoto3(
        tagging_client_factory=lambda: _FakeTaggingClient(resources_by_region),
        ec2_client_factory=lambda: _FakeEC2Client(instances_by_region=instances_by_region),
    )
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    await svc.run_resource_inventory_sync(db_session, connection)

    asset = await db_session.scalar(
        select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:ec2:eu-north-1:123456789012:instance/i-abc")
    )
    assert asset.resource_metadata["security_group_ids"] == ["sg-web", "sg-default"]


async def test_run_resource_inventory_sync_tolerates_failing_describe_security_groups(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    fake_boto3 = _FakeBoto3(ec2_client_factory=lambda: _FakeEC2Client(fail_describe_security_groups=True))
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    synced = await svc.run_resource_inventory_sync(db_session, connection)
    assert synced == 0  # nothing else discovered in this test, but the pass didn't crash


# ── S3 bucket capture + CAN_ACCESS grants (CAN_ACCESS edge's data source) ──

async def test_run_resource_inventory_sync_creates_a_high_value_s3_bucket_asset(db_session, monkeypatch):
    # S3 buckets aren't discovered via the tagging API sync unless they
    # happen to be tagged (confirmed this session, same real gap security
    # groups had) — list_buckets is the only reliable source.
    connection = await _make_connection(db_session)
    fake_boto3 = _FakeBoto3(s3_client=_FakeS3Client(
        buckets=["customer-data"],
        tags_by_bucket={"customer-data": {"Environment": "production", "DataClassification": "customer-pii"}},
    ))
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    await svc.run_resource_inventory_sync(db_session, connection)

    asset = await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:s3:::customer-data"))
    assert asset is not None
    assert asset.resource_type == "s3_bucket"
    assert asset.resource_metadata["tags"]["DataClassification"] == "customer-pii"
    assert asset.is_high_value is True  # no dev/test/staging hint in tags -> heuristic default


async def test_run_resource_inventory_sync_creates_an_untagged_s3_bucket_asset(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    fake_boto3 = _FakeBoto3(s3_client=_FakeS3Client(buckets=["no-tags-bucket"]))  # NoSuchTagSet path
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    await svc.run_resource_inventory_sync(db_session, connection)

    asset = await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == "arn:aws:s3:::no-tags-bucket"))
    assert asset is not None
    assert asset.resource_metadata == {}


async def test_run_resource_inventory_sync_tolerates_failing_list_buckets(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    fake_boto3 = _FakeBoto3(s3_client=_FakeS3Client(fail_list_buckets=True))
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    synced = await svc.run_resource_inventory_sync(db_session, connection)
    assert synced == 0  # nothing else discovered in this test, but the pass didn't crash


async def test_run_resource_inventory_sync_records_can_access_grant_for_high_value_bucket(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    role_arn = "arn:aws:iam::123456789012:role/data-reader"
    bucket_arn = "arn:aws:s3:::customer-data"
    iam_client = _FakeIAMClient(
        roles=[role_arn],
        simulate_responses={(role_arn, bucket_arn): {"s3:GetObject", "s3:ListBucket"}},
    )
    fake_boto3 = _FakeBoto3(
        iam_client=iam_client,
        s3_client=_FakeS3Client(buckets=["customer-data"], tags_by_bucket={"customer-data": {"Environment": "production"}}),
    )
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    await svc.run_resource_inventory_sync(db_session, connection)

    role_asset = await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == role_arn))
    assert role_asset.resource_metadata["can_access"] == [
        {"resource_arn": bucket_arn, "resource_type": "s3_bucket", "actions_allowed": ["s3:GetObject", "s3:ListBucket"]},
    ]
    assert iam_client.simulate_call_count == 1  # exactly one (principal, bucket) pair to check


async def test_run_resource_inventory_sync_skips_simulate_for_a_non_high_value_bucket(db_session, monkeypatch):
    # A bucket tagged "staging" never becomes is_high_value, so it should
    # never even be considered for a CAN_ACCESS grant — zero AWS API calls
    # spent on a bucket that will never render as a crown jewel anyway.
    connection = await _make_connection(db_session)
    iam_client = _FakeIAMClient(roles=["arn:aws:iam::123456789012:role/data-reader"])
    fake_boto3 = _FakeBoto3(
        iam_client=iam_client,
        s3_client=_FakeS3Client(buckets=["staging-data"], tags_by_bucket={"staging-data": {"Environment": "staging"}}),
    )
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    await svc.run_resource_inventory_sync(db_session, connection)

    assert iam_client.simulate_call_count == 0


async def test_run_resource_inventory_sync_tolerates_failing_simulate_principal_policy(db_session, monkeypatch):
    connection = await _make_connection(db_session)
    role_arn = "arn:aws:iam::123456789012:role/data-reader"
    iam_client = _FakeIAMClient(roles=[role_arn], fail_simulate=True)
    fake_boto3 = _FakeBoto3(
        iam_client=iam_client,
        s3_client=_FakeS3Client(buckets=["customer-data"], tags_by_bucket={"customer-data": {"Environment": "production"}}),
    )
    monkeypatch.setattr(svc, "boto3", fake_boto3)

    synced = await svc.run_resource_inventory_sync(db_session, connection)
    assert synced > 0  # the bucket/role still synced fine, only the grant computation degraded

    role_asset = await db_session.scalar(select(CloudAsset).where(CloudAsset.resource_id == role_arn))
    assert "can_access" not in role_asset.resource_metadata
