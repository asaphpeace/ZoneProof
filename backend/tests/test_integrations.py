"""D1: integration framework, exercised with a fake vendor."""
import pytest
from sqlalchemy import select

from app.models import IntegrationConnection
from app.services import integrations
from app.services.integrations import Adapter, FeedSpec, PullResult
from tests.factories import make_tenant, make_user


class FakeVendor(Adapter):
    vendor = "fakevendor"
    label = "Fake Vendor"
    credential_fields = ("api_key", "region")
    feeds = (FeedSpec("messages", "Messages", 600), FeedSpec("threats", "Threats", 3600))
    fail_with: Exception | None = None

    async def test(self, credentials):
        if self.fail_with:
            raise self.fail_with

    async def pull(self, credentials, feed_key, cursor, since):
        if self.fail_with:
            raise self.fail_with
        return PullResult(count=7, cursor=f"after-{cursor or 0}")


@pytest.fixture(autouse=True)
def _vendor():
    saved = dict(integrations._adapters)
    integrations._adapters.clear()
    FakeVendor.fail_with = None
    integrations.register(FakeVendor())
    yield
    integrations._adapters.clear()
    integrations._adapters.update(saved)


SECRET = "sk-live-VERY-SECRET-123"
BODY = {"vendor": "fakevendor", "label": "Prod", "credentials": {"api_key": SECRET, "region": "eu", "extra": "dropped"}}


@pytest.mark.asyncio
async def test_create_stores_credentials_encrypted_and_never_returns_them(auth_client, db_session):
    client, _ = auth_client
    r = await client.post("/integrations", json=BODY)
    assert r.status_code == 201
    assert SECRET not in r.text and "dropped" not in r.text
    assert r.json()["credentials_set"] == ["api_key", "region"]
    assert [f["key"] for f in r.json()["feeds"]] == ["messages", "threats"]

    row = (await db_session.execute(select(IntegrationConnection))).scalar_one()
    assert SECRET not in row.encrypted_credentials and "dropped" not in row.encrypted_credentials
    assert SECRET not in (await client.get("/integrations")).text


@pytest.mark.asyncio
async def test_unknown_vendor_and_missing_fields_are_refused(auth_client):
    client, _ = auth_client
    assert (await client.post("/integrations", json={**BODY, "vendor": "nope"})).status_code == 422
    r = await client.post("/integrations", json={**BODY, "credentials": {"api_key": SECRET}})
    assert r.status_code == 422 and "region" in r.json()["detail"] and SECRET not in r.text


@pytest.mark.asyncio
async def test_run_records_count_cursor_and_status(auth_client):
    client, _ = auth_client
    conn = (await client.post("/integrations", json=BODY)).json()
    feed = conn["feeds"][0]
    r = await client.post(f"/integrations/{conn['id']}/feeds/{feed['id']}/run")
    f = r.json()["feeds"][0]
    assert (f["last_ok"], f["last_count"], f["last_error_kind"]) == (True, 7, None)
    assert r.json()["status"] == "ok" and f["next_run"] is not None
    f2 = (await client.post(f"/integrations/{conn['id']}/feeds/{feed['id']}/run")).json()["feeds"][0]
    assert f2["last_count"] == 7  # cursor was handed back to the adapter on the second pull


@pytest.mark.asyncio
async def test_failures_show_a_fixed_kind_never_vendor_text(auth_client):
    client, _ = auth_client
    conn = (await client.post("/integrations", json=BODY)).json()
    FakeVendor.fail_with = ConnectionError(f"could not reach tenant-x.vendor.internal with {SECRET}")
    t = (await client.post(f"/integrations/{conn['id']}/test")).json()
    assert (t["status"], t["last_error_kind"]) == ("failing", "connection_failed")
    r = await client.post(f"/integrations/{conn['id']}/feeds/{conn['feeds'][0]['id']}/run")
    assert r.status_code == 200 and "vendor.internal" not in r.text and SECRET not in r.text
    assert r.json()["feeds"][0]["last_ok"] is False


@pytest.mark.asyncio
async def test_disable_stops_scheduling_and_interval_is_bounded(auth_client):
    client, _ = auth_client
    conn = (await client.post("/integrations", json=BODY)).json()
    fid = conn["feeds"][0]["id"]
    r = await client.patch(f"/integrations/{conn['id']}/feeds/{fid}", json={"enabled": False})
    assert r.json()["feeds"][0]["enabled"] is False
    assert (await client.patch(f"/integrations/{conn['id']}/feeds/{fid}", json={"interval_seconds": 5})).status_code == 422


@pytest.mark.asyncio
async def test_run_due_pulls_only_enabled_feeds_that_are_due(auth_client, db_session):
    from app.services import integration_service
    client, _ = auth_client
    conn = (await client.post("/integrations", json=BODY)).json()
    await client.patch(f"/integrations/{conn['id']}/feeds/{conn['feeds'][1]['id']}", json={"enabled": False})
    assert await integration_service.run_due(db_session) == 1      # messages never ran; threats is off
    assert await integration_service.run_due(db_session) == 0      # not due again yet


@pytest.mark.asyncio
async def test_other_tenants_and_non_admins_are_kept_out(auth_client, client, db_session):
    owner, _ = auth_client
    conn = (await owner.post("/integrations", json=BODY)).json()

    other = await make_tenant(db_session, name="Other")
    await make_user(db_session, other, email="o@test.com", password="pass123", role="admin")
    viewer = await make_user(db_session, other, email="v@test.com", password="pass123", role="viewer")
    await db_session.flush()

    async def login(email):
        r = await client.post("/auth/token", data={"username": email, "password": "pass123"},
                              headers={"Content-Type": "application/x-www-form-urlencoded"})
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    admin_h, viewer_h = await login("o@test.com"), await login("v@test.com")
    client.headers.pop("Authorization", None)
    assert (await client.get("/integrations", headers=admin_h)).json() == []
    assert (await client.post(f"/integrations/{conn['id']}/test", headers=admin_h)).status_code == 404
    assert (await client.delete(f"/integrations/{conn['id']}", headers=admin_h)).status_code == 404
    assert (await client.get("/integrations", headers=viewer_h)).status_code == 403
