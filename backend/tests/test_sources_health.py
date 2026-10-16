"""Data sources and health: what is flowing, what is not, and nothing sensitive."""
from datetime import datetime, timedelta, timezone

import pytest

from app.services import job_registry
from tests.factories import make_dmarc_report, make_domain, make_tenant, make_user


@pytest.fixture(autouse=True)
def _fresh_registry():
    saved = dict(job_registry._jobs)
    job_registry.reset()
    yield
    job_registry._jobs.clear()
    job_registry._jobs.update(saved)


# ── the registry ─────────────────────────────────────────────────────────────

def test_successful_run_is_recorded():
    job_registry.register("j", "Job", "x", lambda: 60)
    job_registry.start("j")
    job_registry.finish("j")
    j = job_registry.snapshot()[0]
    assert (j.runs, j.failures, j.last_ok) == (1, 0, True)
    assert j.last_finished is not None and j.last_failure_kind is None


def test_a_failure_the_job_caught_still_counts_as_failed():
    """Jobs catch their own exceptions, so the run must be marked failed by fail()."""
    job_registry.register("j", "Job", "x", lambda: 60)
    job_registry.start("j")
    job_registry.fail("j", ConnectionError("could not reach mail.internal.example:993"))
    job_registry.finish("j")
    j = job_registry.snapshot()[0]
    assert (j.last_ok, j.failures, j.last_failure_kind) == (False, 1, "connection_failed")


def test_a_later_good_run_clears_the_failure():
    job_registry.register("j", "Job", "x", lambda: 60)
    job_registry.start("j"); job_registry.fail("j", TimeoutError()); job_registry.finish("j")
    job_registry.start("j"); job_registry.finish("j")
    j = job_registry.snapshot()[0]
    assert (j.last_ok, j.last_failure_kind, j.failures, j.runs) == (True, None, 1, 2)


@pytest.mark.parametrize("exc,kind", [
    (TimeoutError("x"), "timed_out"),
    (Exception("operation timed out"), "timed_out"),
    (Exception("authentication failed for reports@example.com"), "login_rejected"),
    (ConnectionRefusedError("refused"), "connection_failed"),
    (ValueError("anything else"), "unexpected"),
    (None, "unexpected"),
])
def test_failure_kinds(exc, kind):
    assert job_registry.classify(exc) == kind


def test_no_exception_text_survives():
    job_registry.register("j", "Job", "x", lambda: 60)
    job_registry.start("j")
    job_registry.fail("j", RuntimeError("password=hunter2 host=10.0.0.5"))
    job_registry.finish("j")
    j = job_registry.snapshot()[0]
    assert "hunter2" not in repr(j) and "10.0.0.5" not in repr(j)


# ── the endpoint ─────────────────────────────────────────────────────────────

async def test_requires_admin(client, db_session):
    tenant = await make_tenant(db_session, name="Members Only")
    await make_user(db_session, tenant, email="member@test.com", password="pass123", role="viewer")
    await db_session.flush()
    resp = await client.post("/auth/token", data={"username": "member@test.com", "password": "pass123"},
                             headers={"Content-Type": "application/x-www-form-urlencoded"})
    client.headers.update({"Authorization": f"Bearer {resp.json()['access_token']}"})
    assert (await client.get("/sources/health")).status_code == 403


async def test_empty_workspace_reports_nothing_received(auth_client):
    client, _ = auth_client
    body = (await client.get("/sources/health")).json()
    assert {d["key"] for d in body["data"]} == {"dmarc_reports", "tls_reports", "certificates", "dns_checks"}
    assert all(d["status"] == "none" for d in body["data"])
    assert {i["key"] for i in body["integrations"]} >= {"report_inbox", "email", "advisor"}


async def test_data_freshness_per_domain(auth_client, db_session):
    client, tenant = auth_client
    fresh = await make_domain(db_session, tenant, name="fresh.test")
    old = await make_domain(db_session, tenant, name="old.test")
    await make_dmarc_report(db_session, fresh, days_ago=0)
    r = await make_dmarc_report(db_session, old, days_ago=10)
    r.received_at = datetime.now(timezone.utc) - timedelta(days=10)
    await db_session.flush()

    block = next(d for d in (await client.get("/sources/health")).json()["data"] if d["key"] == "dmarc_reports")
    by_domain = {i["domain"]: i for i in block["domains"]}
    assert by_domain["fresh.test"]["status"] == "ok"
    assert by_domain["old.test"]["status"] == "stale"
    assert block["status"] == "stale"
    assert by_domain["fresh.test"]["count"] == 1


async def test_only_this_workspaces_domains_are_listed(auth_client, db_session):
    client, tenant = auth_client
    await make_domain(db_session, tenant, name="mine.test")
    other = await make_tenant(db_session, name="Other Workspace")
    await make_domain(db_session, other, name="theirs.test")
    body = (await client.get("/sources/health")).json()
    names = {i["domain"] for d in body["data"] for i in d["domains"]}
    assert names == {"mine.test"}


async def test_job_states_and_failure_text(auth_client):
    client, _ = auth_client
    job_registry.register("a", "Alpha", "x", lambda: 3600)
    job_registry.register("b", "Beta", "x", lambda: 3600)
    job_registry.start("a"); job_registry.finish("a")
    job_registry.start("b"); job_registry.fail("b", RuntimeError("secret detail at /srv/app/x.py")); job_registry.finish("b")
    jobs = {j["key"]: j for j in (await client.get("/sources/health")).json()["jobs"]}
    assert jobs["a"]["status"] == "ok"
    assert jobs["b"]["status"] == "failing"
    assert "secret detail" not in str(jobs["b"]) and "/srv/app" not in str(jobs["b"])
    assert jobs["b"]["note"]            # a plain-language reason is present
    assert jobs["a"]["next_run"] is not None


async def test_a_job_that_has_not_run_yet_is_waiting_not_ok(auth_client):
    client, _ = auth_client
    job_registry.register("never", "Never", "x", lambda: 86400)
    job = next(j for j in (await client.get("/sources/health")).json()["jobs"] if j["key"] == "never")
    assert job["status"] == "waiting" and job["last_finished"] is None
