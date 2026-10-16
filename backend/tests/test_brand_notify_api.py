import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select

from app.models import Alert, BrandNotifyChannel, BrandNotifyLog
from app.services import brand_notify as bn
from app.services import brand_notify_dispatch as nd
from app.services.crypto_service import decrypt_secret
from tests.test_brand_guard_api import _pro_profile

SLACK = "https://hooks.slack.com/services/T0/B0/abcd1234"


async def _tenant_id(client, tenant, db_session):
    await _pro_profile(client, tenant, db_session)
    return tenant.id


async def test_channel_is_validated_encrypted_masked_and_a_webhook_secret_is_shown_once(auth_client, db_session):
    client, tenant = auth_client
    await _tenant_id(client, tenant, db_session)
    bad = await client.post("/brand-guard/notification-channels", json={"kind": "webhook", "label": "x", "target": "http://example.com/h"})
    assert bad.status_code == 422 and "https" in bad.json()["detail"]
    assert (await client.post("/brand-guard/notification-channels", json={"kind": "slack", "label": "x", "target": "https://example.com/x"})).status_code == 422
    ok = (await client.post("/brand-guard/notification-channels", json={"kind": "webhook", "label": "SIEM", "target": "https://siem.example.com/hook/secretpart1234", "min_severity": "critical"})).json()
    assert ok["secret"] and ok["signed"] and "secretpart" not in json.dumps(ok) and ok["target"].startswith("siem.example.com/…") and ok["target"].endswith("1234")
    listed = (await client.get("/brand-guard/notification-channels")).json()
    assert len(listed) == 1 and "secret" not in listed[0]
    row = (await db_session.execute(select(BrandNotifyChannel))).scalars().one()
    assert "siem.example.com" not in row.target_enc and decrypt_secret(row.target_enc).endswith("secretpart1234") and decrypt_secret(row.secret_enc) == ok["secret"]
    em = (await client.post("/brand-guard/notification-channels", json={"kind": "email", "label": "Ops", "target": "Ops@Example.com"})).json()
    assert em["target"] == "op…@example.com" and em["secret"] is None and not em["signed"]


async def test_channel_limit_update_delete_and_tenant_isolation(auth_client, db_session):
    client, tenant = auth_client
    await _tenant_id(client, tenant, db_session)
    ids = []
    for i in range(10):
        ids.append((await client.post("/brand-guard/notification-channels", json={"kind": "email", "label": f"c{i}", "target": f"c{i}@example.com"})).json()["id"])
    assert (await client.post("/brand-guard/notification-channels", json={"kind": "email", "label": "11th", "target": "x@example.com"})).status_code == 409
    upd = (await client.patch(f"/brand-guard/notification-channels/{ids[0]}", json={"enabled": False, "digest": True, "min_severity": "critical"})).json()
    assert (upd["enabled"], upd["digest"], upd["min_severity"]) == (False, True, "critical")
    assert (await client.patch(f"/brand-guard/notification-channels/{ids[0]}", json={"min_severity": "info"})).status_code == 422
    assert (await client.delete(f"/brand-guard/notification-channels/{ids[1]}")).status_code == 204
    other = str(uuid.uuid4())
    assert (await client.patch(f"/brand-guard/notification-channels/{other}", json={"enabled": False})).status_code == 404
    assert (await client.delete(f"/brand-guard/notification-channels/{other}")).status_code == 404
    assert (await client.post(f"/brand-guard/notification-channels/{other}/test")).status_code == 404


class _Fake:
    def __init__(self):
        self.calls = []

    async def post(self, url, content=None, headers=None, **kw):
        self.calls.append((url, content, headers))
        return httpx.Response(200)


async def test_webhook_delivery_is_signed_public_only_and_never_follows_redirects(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    await _tenant_id(client, tenant, db_session)
    made = (await client.post("/brand-guard/notification-channels", json={"kind": "webhook", "label": "w", "target": "https://hook.example.com/in"})).json()
    ch = await db_session.get(BrandNotifyChannel, uuid.UUID(made["id"]))
    fake = _Fake()
    seen = {}
    orig = httpx.AsyncClient.__init__

    def spy(self, *a, **k):
        seen.update(k)
        orig(self, *a, **k)
    monkeypatch.setattr(httpx.AsyncClient, "__init__", spy)
    monkeypatch.setattr(httpx.AsyncClient, "post", lambda self, *a, **k: fake.post(*a, **k))

    async def public(host): return True
    monkeypatch.setattr(bn, "host_resolves_publicly", public)
    alert = {"id": "a1", "severity": "critical", "title": "T", "body": "B", "action": None, "created_at": "2026-10-06T00:00:00+00:00"}
    ok, err = await nd.deliver(db_session, ch, alert, "https://app.example.com/brand-guard")
    assert ok and err is None and seen["follow_redirects"] is False
    url, body, headers = fake.calls[0]
    assert url == "https://hook.example.com/in" and json.loads(body)["type"] == "brand_guard.alert"
    assert bn.verify(body, made["secret"], headers["X-ZoneProof-Timestamp"], headers["X-ZoneProof-Signature"])

    async def private(host): return False
    monkeypatch.setattr(bn, "host_resolves_publicly", private)
    fake.calls.clear()
    ok, err = await nd.deliver(db_session, ch, alert, None)
    assert not ok and "public" in err and fake.calls == []                # nothing was sent to a non-public host


async def test_non_2xx_and_exceptions_are_reported_not_raised(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    await _tenant_id(client, tenant, db_session)
    made = (await client.post("/brand-guard/notification-channels", json={"kind": "slack", "label": "s", "target": SLACK})).json()
    ch = await db_session.get(BrandNotifyChannel, uuid.UUID(made["id"]))

    async def public(host): return True
    monkeypatch.setattr(bn, "host_resolves_publicly", public)

    async def post500(self, *a, **k): return httpx.Response(500)
    monkeypatch.setattr(httpx.AsyncClient, "post", post500)
    assert await nd.deliver(db_session, ch, {"id": "x", "severity": "warn", "title": "t", "body": "b", "action": None, "created_at": ""}, None) == (False, "The receiver answered HTTP 500")

    async def boom(self, *a, **k): raise httpx.ConnectError("secret-host-detail")
    monkeypatch.setattr(httpx.AsyncClient, "post", boom)
    ok, err = await nd.deliver(db_session, ch, {"id": "x", "severity": "warn", "title": "t", "body": "b", "action": None, "created_at": ""}, None)
    assert not ok and err == "Could not send (ConnectError)" and "secret-host-detail" not in err        # no internal detail leaks to the person


async def _alerts(db_session, tenant_id, specs):
    for sev, title, age_h in specs:
        db_session.add(Alert(id=uuid.uuid4(), tenant_id=tenant_id, severity=sev, category="brand", title=title, body="b", created_at=datetime.now(timezone.utc) - timedelta(hours=age_h)))
    await db_session.commit()


async def test_dispatch_sends_each_alert_once_respects_severity_and_age_and_other_categories(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    await _tenant_id(client, tenant, db_session)
    await client.post("/brand-guard/notification-channels", json={"kind": "slack", "label": "s", "target": SLACK, "min_severity": "critical"})
    await client.post("/brand-guard/notification-channels", json={"kind": "email", "label": "e", "target": "e@example.com", "min_severity": "warn"})
    await _alerts(db_session, tenant.id, [("critical", "crit", 1), ("warn", "warn", 1), ("critical", "too-old", 72)])
    db_session.add(Alert(id=uuid.uuid4(), tenant_id=tenant.id, severity="critical", category="dmarc", title="not brand", body="b"))
    await db_session.commit()
    sent = []

    async def fake(db, channel, alert, link=None):
        sent.append((channel.kind, alert["title"]))
        return True, None
    monkeypatch.setattr(nd, "deliver", fake)
    assert await nd.dispatch_new(db_session, tenant.id) == 3
    assert sorted(sent) == [("email", "crit"), ("email", "warn"), ("slack", "crit")]
    sent.clear()
    assert await nd.dispatch_new(db_session, tenant.id) == 0 and sent == []             # nothing is sent twice
    log = (await client.get("/brand-guard/notification-log")).json()
    assert len(log) == 3 and all(r["status"] == "ok" and r["type"] == "alert" for r in log)


async def test_a_failing_channel_gets_one_failure_per_pass_and_is_retried_later_without_blocking_others(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    await _tenant_id(client, tenant, db_session)
    bad = (await client.post("/brand-guard/notification-channels", json={"kind": "slack", "label": "down", "target": SLACK})).json()
    await client.post("/brand-guard/notification-channels", json={"kind": "email", "label": "up", "target": "u@example.com"})
    await _alerts(db_session, tenant.id, [("critical", "a", 1), ("critical", "b", 1), ("critical", "c", 1)])
    state = {"slack_up": False}

    async def fake(db, channel, alert, link=None):
        if channel.kind == "slack" and not state["slack_up"]:
            return False, "The receiver answered HTTP 500"
        return True, None
    monkeypatch.setattr(nd, "deliver", fake)
    assert await nd.dispatch_new(db_session, tenant.id) == 3                              # the email channel got all three
    fails = (await db_session.execute(select(BrandNotifyLog).where(BrandNotifyLog.status == "failed"))).scalars().all()
    assert len(fails) == 1                                                                 # one failure for the down channel, not three
    ch = await db_session.get(BrandNotifyChannel, uuid.UUID(bad["id"]))
    await db_session.refresh(ch)
    assert ch.last_status == "failed" and "500" in ch.last_error
    state["slack_up"] = True
    assert await nd.dispatch_new(db_session, tenant.id) == 3                              # recovered: it now catches up on all three


async def test_disabled_channels_get_nothing_and_a_test_message_is_logged(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    await _tenant_id(client, tenant, db_session)
    ch = (await client.post("/brand-guard/notification-channels", json={"kind": "email", "label": "e", "target": "e@example.com"})).json()
    await client.patch(f"/brand-guard/notification-channels/{ch['id']}", json={"enabled": False})
    await _alerts(db_session, tenant.id, [("critical", "a", 1)])
    called = []

    async def fake(db, channel, alert, link=None):
        called.append(alert["id"])
        return True, None
    monkeypatch.setattr(nd, "deliver", fake)
    assert await nd.dispatch_new(db_session, tenant.id) == 0 and called == []
    r = (await client.post(f"/brand-guard/notification-channels/{ch['id']}/test")).json()
    assert r == {"ok": True, "error": None} and called == ["test"]
    assert (await client.get("/brand-guard/notification-log")).json()[0]["type"] == "test"


async def test_digest_goes_to_digest_channels_once_a_day(auth_client, db_session, monkeypatch):
    client, tenant = auth_client
    await _tenant_id(client, tenant, db_session)
    await client.post("/brand-guard/notification-channels", json={"kind": "email", "label": "d", "target": "d@example.com", "digest": True})
    await client.post("/brand-guard/notification-channels", json={"kind": "email", "label": "n", "target": "n@example.com", "digest": False})
    got = []

    async def fake(db, channel, alert, link=None):
        got.append((channel.kind, alert["title"], alert["body"]))
        return True, None
    monkeypatch.setattr(nd, "deliver", fake)
    assert await nd.send_due_digests(db_session) == 1 and len(got) == 1 and got[0][1].startswith("ZoneProof daily summary for ")
    assert await nd.send_due_digests(db_session) == 0                                     # not again within 24 hours


async def test_siem_export_is_enterprise_only_and_emits_alerts_and_audit_events(auth_client, db_session):
    from app.models.user import Tenant
    client, tenant = auth_client
    await _tenant_id(client, tenant, db_session)
    denied = await client.get("/brand-guard/siem-export")
    assert denied.status_code == 403 and denied.json()["detail"]["upgrade_required"]
    row = await db_session.get(Tenant, tenant.id)
    row.plan = "enterprise"
    await db_session.commit()
    await _alerts(db_session, tenant.id, [("critical", "Possible brand impersonation: a=b|c.xyz", 1)])
    await client.post("/brand-guard/notification-channels", json={"kind": "email", "label": "e", "target": "e@example.com"})
    lines = [json.loads(l) for l in (await client.get("/brand-guard/siem-export?format=jsonl")).text.splitlines()]
    kinds = {l["kind"] for l in lines}
    assert "brand_guard.alert" in kinds and "brand_guard.channel_added" in kinds
    cef = (await client.get("/brand-guard/siem-export?format=cef")).text.splitlines()
    assert all(l.startswith("CEF:0|ZoneProof|Brand Guard|1|") for l in cef) and any("a\\|b" not in l and "msg=b" in l for l in cef)
    assert (await client.get("/brand-guard/siem-export?format=xml")).status_code == 422
    assert (await client.get("/brand-guard/siem-export?since=garbage")).status_code == 422
    assert [l["kind"] for l in (json.loads(x) for x in (await client.get("/brand-guard/siem-export?since=2999-01-01T00:00:00Z")).text.splitlines())] == []
