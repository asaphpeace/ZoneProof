"""Step 7.4 end to end on the API side: similarity facts from a light probe and a rendered page, the evidence lines they produce (and the one that
deliberately carries no weight), the reference render of the customer's own page, and how a new reference updates look-alikes already rendered."""
import base64
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.config import settings
from app.models import BrandCandidate, BrandPageCapture, BrandProbeJob, BrandProfile, BrandReferenceCapture, CandidateEvidence
from app.services import brand_capture as bc
from app.services import brand_fingerprint_service as fps
from app.services import brand_probe_analysis as pa
from app.services import brand_probe_protocol as pp
from app.services import brand_probe_queue as q
from app.services import brand_similarity as bs
from tests.test_brand_render_data import _cand, _claimed, _render_job, raw_render, render_on, on                     # noqa: F401
from tests.test_brand_probe_queue import NOW
from tests.test_brand_similarity import HOME, enc, logo, page


def b64(b):
    return base64.b64encode(b).decode()


BRAND_ICON = enc(logo(11))
BRAND_PAGE = enc(page())
REF = {"icon_dhash": bs.dhash(BRAND_ICON, 8), "wording": bs.shingles(HOME), "layout": bs.dhash(BRAND_PAGE, 16), "palette": bs.palette(BRAND_PAGE)}
COPY_HTML = "<html><title>Sign in</title><body><p>" + HOME + " please sign in below</p></body></html>"


def light(html=COPY_HTML, favicon=None):
    r = {"ok": True, "chain": [{"url": "http://live.xyz/", "status": 200}], "final_status": 200, "content_type": "text/html", "html": html}
    if favicon is not None:
        r["favicon_b64"] = b64(favicon)
    return r


def analyse(result, ref=REF, **kw):
    a = dict(host="live.xyz", official_domains=["acme.com"], brand_words=["acme"], brand_favicon_sha256=None, brand_ref=ref)
    a.update(kw)
    return pa.analyse(pp.clean_result(result), **a)


def sigs(facts):
    return {s["signal"]: s for s in pa.signals(facts)}


# ── light probe ────────────────────────────────────────────────────────────

def test_a_re_sized_copy_of_the_icon_and_reused_wording_are_found_and_scored_modestly():
    f = analyse(light(favicon=enc(logo(11).resize((32, 32)))))
    assert f["similarity"]["icon"]["similar"] and f["similarity"]["wording"]["shared"] > 0.9
    s = sigs(f)
    assert s["page_icon_lookalike"]["weight"] == pa.W_ICON_LOOKALIKE == 8.0 < pa.W_PASSWORD_FORM + pa.W_OFFSITE_FORM
    assert s["page_copies_wording"]["weight"] == pa.W_WORDING_STRONG and "%" in s["page_copies_wording"]["summary"] and all(x["dimension"] == "abuse" for x in s.values())


def test_wording_weight_steps_with_how_much_is_shared_and_nothing_is_said_below_the_threshold():
    half = HOME[: len(HOME) // 2] + " " + " ".join(f"other{i} thing{i % 5} here{i % 9}" for i in range(110))
    f = analyse(light(f"<p>{half}</p>"))
    shared = f["similarity"]["wording"]["shared"]
    s = sigs(f)
    expected = pa.W_WORDING_STRONG if shared >= bs.WORDING_STRONG else pa.W_WORDING_COPY if shared >= bs.WORDING_COPY else None
    assert (s["page_copies_wording"]["weight"] if "page_copies_wording" in s else None) == expected
    unrelated = analyse(light("<p>" + " ".join(f"zebra{i} quartz{i % 7} lemon{i % 11}" for i in range(300)) + "</p>"))
    assert "page_copies_wording" not in sigs(unrelated) and unrelated["similarity"]["wording"]["shared"] < 0.05
    some = analyse(light("<p>" + HOME[: len(HOME) // 6] + " " + " ".join(f"fresh{i} novel{i % 7} words{i % 13}" for i in range(260)) + "</p>"))
    assert 0.05 < some["similarity"]["wording"]["shared"] < bs.WORDING_COPY and "page_copies_wording" not in sigs(some)       # some overlap is not a copy


def test_an_exact_icon_copy_is_one_line_not_two_and_an_unrelated_icon_is_nothing():
    exact_sha = hashlib.sha256(BRAND_ICON).hexdigest()
    s = sigs(analyse(light(favicon=BRAND_ICON), brand_favicon_sha256=exact_sha))
    assert "page_brand_favicon" in s and "page_icon_lookalike" not in s
    assert "page_icon_lookalike" not in sigs(analyse(light(favicon=enc(logo(12)))))


def test_without_a_reference_or_with_blank_images_no_similarity_is_claimed():
    f = analyse(light(favicon=BRAND_ICON), ref=None)
    assert f["similarity"] == {} and not ({"page_icon_lookalike", "page_copies_wording"} & set(sigs(f)))
    blank = enc(__import__("PIL.Image", fromlist=["new"]).new("RGB", (32, 32), "white"))
    f2 = analyse(light(favicon=blank), ref={**REF, "icon_dhash": bs.dhash(blank, 8)})
    assert "icon" not in f2["similarity"]                                  # two blank icons would "match": the guard refuses
    assert analyse(light(), ref={"icon_dhash": None, "wording": []})["similarity"] == {}


def test_a_redirect_to_the_brand_explains_everything_away_including_similarity():
    r = light()
    r["chain"] = [{"url": "http://live.xyz/", "status": 301}, {"url": "https://www.acme.com/", "status": 200}]
    assert [s for s in sigs(analyse(r))] == ["page_redirects_to_brand"]


def test_the_stored_facts_hold_hashes_and_numbers_never_the_pages_words():
    f = analyse(light(favicon=BRAND_ICON))
    assert "please sign in below" not in json.dumps(f) and "html" not in f and f["favicon_dhash"] == bs.dhash(BRAND_ICON, 8)


# ── rendered page ──────────────────────────────────────────────────────────

def rendered(shot=BRAND_PAGE, text=HOME, ref=REF):
    r = pp.clean_render(raw_render(screenshot_b64=b64(shot), text=text))
    return pa.analyse_render(r, host="live.xyz", official_domains=["acme.com"], brand_words=["acme"], brand_ref=ref)


def test_a_screenshot_with_the_brands_layout_and_colours_is_shown_but_carries_no_weight():
    clone = enc(page().convert("RGB"), "JPEG", quality=60)
    r = rendered(clone)
    assert r["similarity"]["visual"]["similar"] and r["layout"] == bs.dhash(clone, 16) and r["palette"] == bs.palette(clone)
    merged = pa.merge_render({"reachable": True, "similarity": {}}, r)
    s = sigs(merged)
    assert s["page_looks_like_brand"]["weight"] == 0.0 and "not scored" in s["page_looks_like_brand"]["summary"]


def test_the_same_template_in_other_colours_is_not_called_a_look_alike_of_the_page():
    template = enc(page(c1="#1a8f3c", c2="#8f1a5e"))
    r = rendered(template)
    assert r["similarity"]["visual"]["similar"] is False
    assert "page_looks_like_brand" not in sigs(pa.merge_render({"reachable": True}, r))


def test_merge_keeps_the_better_wording_and_the_rendered_visual_and_drops_a_stale_one():
    light_facts = {"reachable": True, "similarity": {"wording": {"shared": 0.2, "n": 50}, "visual": {"layout": 0.0, "palette": 1.0, "similar": True}}}
    m = pa.merge_render(light_facts, rendered(enc(page(layout=1)), text=HOME))
    assert m["similarity"]["wording"]["shared"] > 0.9 and m["similarity"]["visual"]["similar"] is False
    no_visual = pa.merge_render(light_facts, rendered(enc(page()), ref={**REF, "layout": None}))
    assert "visual" not in no_visual["similarity"]
    half = HOME[: len(HOME) // 2] + " " + " ".join(f"other{i} thing{i % 5} here{i % 9}" for i in range(110))
    worse = pa.merge_render({"reachable": True, "similarity": {"wording": {"shared": 0.95, "n": 80}}}, rendered(text=half))
    assert 0.2 < rendered(text=half)["similarity"]["wording"]["shared"] < 0.95 and worse["similarity"]["wording"]["shared"] == 0.95     # the plain page's better overlap is kept


def test_recompare_visual_redoes_the_comparison_against_a_new_reference_and_tolerates_none():
    r = rendered(enc(page().convert("RGB"), "JPEG", quality=60), ref={**REF, "layout": None, "palette": None})
    assert "visual" not in r["similarity"]
    again = pa.recompare_visual(r, REF)
    assert again["similarity"]["visual"]["similar"] and again is not r and "visual" not in r["similarity"]
    assert "visual" not in pa.recompare_visual(again, {})["similarity"] and pa.recompare_visual(None, REF) is None


# ── brand reference ────────────────────────────────────────────────────────

async def _profile_of(db, row):
    return await db.get(BrandProfile, row.profile_id)


async def test_the_brand_reference_combines_the_fingerprints_hashes_with_the_captured_page(db_session, render_on):
    profile, row = await _cand(db_session)
    assert await q.brand_ref(db_session, profile) == {"icon_dhash": None, "wording": []}
    profile.fingerprint = {"similarity": {"icon_dhash": REF["icon_dhash"], "wording": REF["wording"]}}
    await bc.store_reference(db_session, profile=profile, shot_b64=b64(BRAND_PAGE), layout=REF["layout"], palette=REF["palette"], now=NOW)
    await db_session.commit()
    assert await q.brand_ref(db_session, profile) == REF


async def test_a_reference_render_is_queued_for_the_brands_own_domain_once_and_refreshed_when_old(db_session, render_on):
    profile, _ = await _cand(db_session)
    assert await q.enqueue_reference(db_session, profile, NOW) is True
    await db_session.commit()
    job = (await db_session.execute(select(BrandProbeJob).where(BrandProbeJob.kind == "ref"))).scalar_one()
    from app.models import Domain
    assert job.candidate_id is None and job.profile_id == profile.id and job.host == (await db_session.get(Domain, profile.domain_id)).name
    assert await q.enqueue_reference(db_session, profile, NOW) is False                       # already waiting
    job.status = "done"
    await bc.store_reference(db_session, profile=profile, shot_b64=b64(BRAND_PAGE), layout=REF["layout"], palette=REF["palette"], now=NOW)
    await db_session.commit()
    assert await q.enqueue_reference(db_session, profile, NOW + timedelta(days=5)) is False   # fresh enough
    assert await q.enqueue_reference(db_session, profile, NOW + timedelta(days=settings.brand_reference_refresh_days + 1)) is True


async def test_no_reference_is_queued_while_the_renderer_is_off(db_session, on):               # noqa: F811
    profile, _ = await _cand(db_session)
    assert await q.enqueue_reference(db_session, profile, NOW) is False
    assert (await db_session.execute(select(BrandProbeJob))).scalars().all() == []


async def test_a_reference_job_is_handed_to_the_worker_only_when_the_renderer_is_on(db_session, on, monkeypatch):      # noqa: F811
    profile, _ = await _cand(db_session)
    j = BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=None, profile_id=profile.id, host="acmefinancial.co.za", kind="ref", status="queued", expires_at=NOW + timedelta(days=1))
    db_session.add(j)
    await db_session.commit()
    assert await q.claim(db_session) is None
    monkeypatch.setattr(settings, "brand_render_enabled", True)
    got = await q.claim(db_session)
    assert got.id == j.id and got.kind == "ref"


async def _ref_job(db, profile):
    j = BrandProbeJob(id=uuid.uuid4(), tenant_id=profile.tenant_id, candidate_id=None, profile_id=profile.id, host="acmefinancial.co.za", kind="ref", status="claimed", claimed_at=NOW, expires_at=NOW + timedelta(days=1))
    db.add(j)
    await db.commit()
    return j


async def test_a_reference_result_is_stored_encrypted_with_its_hashes(db_session, render_on):
    profile, _ = await _cand(db_session)
    job = await _ref_job(db_session, profile)
    assert await q.complete(db_session, job.id, {"ok": True, "render": raw_render(screenshot_b64=b64(BRAND_PAGE))}) == "ok"
    await db_session.refresh(job)
    row = (await db_session.execute(select(BrandReferenceCapture))).scalar_one()
    assert job.status == "done" and row.profile_id == profile.id and row.layout_hash == bs.dhash(BRAND_PAGE, 16) and row.palette == bs.palette(BRAND_PAGE)
    assert b64(BRAND_PAGE)[:40] not in row.screenshot_enc and bc.reference_bytes(row) == BRAND_PAGE
    job2 = await _ref_job(db_session, profile)                                                  # a refresh replaces, never duplicates
    await q.complete(db_session, job2.id, {"ok": True, "render": raw_render(screenshot_b64=b64(enc(page(layout=1))))})
    rows = (await db_session.execute(select(BrandReferenceCapture))).scalars().all()
    assert len(rows) == 1 and rows[0].layout_hash == bs.dhash(enc(page(layout=1)), 16)


async def test_only_a_real_image_is_ever_kept_as_the_reference(db_session):
    profile, _ = await _cand(db_session)
    assert await bc.store_reference(db_session, profile=profile, shot_b64=b64(b"<html><script>alert(1)</script></html>"), layout=None, palette=None) is None
    assert (await db_session.execute(select(BrandReferenceCapture))).scalars().all() == []


async def test_a_failed_or_imageless_reference_result_stores_nothing(db_session, render_on):
    profile, _ = await _cand(db_session)
    for result in ({"ok": False, "error": "render timed out"}, {"ok": True}, {"ok": True, "render": {"title": "T"}}):
        job = await _ref_job(db_session, profile)
        assert await q.complete(db_session, job.id, result) == "ok"
        await db_session.refresh(job)
        assert job.status == "failed" and job.error
    assert (await db_session.execute(select(BrandReferenceCapture))).scalars().all() == []


async def test_a_reference_result_is_refused_when_the_renderer_is_off(db_session, on):          # noqa: F811
    profile, _ = await _cand(db_session)
    job = await _ref_job(db_session, profile)
    assert await q.complete(db_session, job.id, {"ok": True, "render": raw_render(screenshot_b64=b64(BRAND_PAGE))}) == "disabled"


async def test_a_new_reference_updates_look_alikes_already_rendered_and_rescores_them(db_session, render_on):
    profile, row = await _cand(db_session)
    row.enrichment = {"probe": {"reachable": True, "password_form": False, "forms": [], "brand_in_title": False, "similarity": {}}}      # (a render only follows a light probe)
    await db_session.commit()
    clone = enc(page().convert("RGB"), "JPEG", quality=60)
    render_job = await _render_job(db_session, profile, row)
    await q.complete(db_session, render_job.id, {"ok": True, "render": raw_render(screenshot_b64=b64(clone))})
    await db_session.refresh(row)
    probe = row.enrichment["probe"]
    assert probe["rendered"]["layout"] == bs.dhash(clone, 16) and "visual" not in probe["similarity"] and probe["form_after_scripts"] in (True, False)
    before = probe["form_after_scripts"]
    ref_job = await _ref_job(db_session, profile)
    await q.complete(db_session, ref_job.id, {"ok": True, "render": raw_render(screenshot_b64=b64(BRAND_PAGE))})
    await db_session.refresh(row)
    after = row.enrichment["probe"]
    assert after["similarity"]["visual"]["similar"] is True and after["form_after_scripts"] == before and after["rendered"]["password_form"] == probe["rendered"]["password_form"]
    ev = {e.signal: e for e in (await db_session.execute(select(CandidateEvidence).where(CandidateEvidence.candidate_id == row.id))).scalars().all()}
    assert ev["page_looks_like_brand"].weight == 0.0


async def test_a_light_result_is_compared_with_the_brand_and_the_evidence_is_scored(db_session, render_on):
    profile, row = await _cand(db_session)
    profile.fingerprint = {"similarity": {"icon_dhash": REF["icon_dhash"], "wording": REF["wording"]}}
    await db_session.commit()
    job = await _claimed(db_session, profile, row)
    assert await q.complete(db_session, job.id, light(favicon=enc(logo(11).resize((48, 48))))) == "ok"
    await db_session.refresh(row)
    assert row.enrichment["probe"]["similarity"]["icon"]["similar"] and row.enrichment["probe"]["similarity"]["wording"]["shared"] > 0.9
    ev = {e.signal: e for e in (await db_session.execute(select(CandidateEvidence).where(CandidateEvidence.candidate_id == row.id))).scalars().all()}
    assert ev["page_icon_lookalike"].weight == 8.0 and ev["page_copies_wording"].weight == 14.0 and all(ev[k].dimension == "abuse" for k in ("page_icon_lookalike", "page_copies_wording"))
    assert "please sign in below" not in json.dumps(row.enrichment)


# ── fingerprint and API ────────────────────────────────────────────────────

class _Res:
    def __init__(self, url, body, ctype="text/html", status=200):
        self.url, self.body, self.content_type, self.status, self.truncated = url, body, ctype, status, False


async def test_the_fingerprint_keeps_hashes_of_the_icon_and_wording_apart_from_the_site_facts():
    html = ("<html><head><title>Acme</title><link rel='icon' href='/i.png'></head><body><p>" + HOME + "</p><script>var secret='SCRIPTWORDS one two three four';</script></body></html>").encode()
    pages = {"https://acme.co.za/": _Res("https://acme.co.za/", html), "https://acme.co.za/i.png": _Res("https://acme.co.za/i.png", BRAND_ICON, "image/png")}

    async def fetch(url, **kw):
        return pages[url]

    async def query(name, rtype):
        return ("ok", [])
    fp = await fps.build_fingerprint("acme.co.za", fetch=fetch, query=query)
    sim = fp["similarity"]
    assert sim["icon_dhash"] == bs.dhash(BRAND_ICON, 8) and sim["wording_n"] == len(sim["wording"]) > 100 and "_wording" not in fp["site"]
    assert sim["wording"] == bs.shingles(HOME) and fp["site"]["favicon"]["dhash"] == sim["icon_dhash"]
    assert "SCRIPTWORDS" not in json.dumps(fp)                                       # scripts are not wording, and no words are stored at all
    none = await fps.build_fingerprint("acme.co.za", fetch=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")), query=query)
    assert none["similarity"] == {"icon_dhash": None, "wording": [], "wording_n": 0}


async def test_the_profile_api_does_not_expose_the_hashed_comparison_data(auth_client, db_session):
    from tests.test_brand_guard_api import _pro_profile
    client, tenant = auth_client
    pid = await _pro_profile(client, tenant, db_session)
    p = await db_session.get(BrandProfile, uuid.UUID(pid))
    p.fingerprint = {"version": 1, "domain": "x", "site": None, "dns": {}, "errors": [], "similarity": {"icon_dhash": "ab", "wording": ["deadbeef"], "wording_n": 1}}
    await db_session.commit()
    listed = (await client.get("/brand-guard/profiles")).json()[0]
    assert listed["fingerprint"]["domain"] == "x" and "similarity" not in listed["fingerprint"] and "deadbeef" not in json.dumps(listed)


async def test_the_reference_screenshot_is_served_as_an_image_only_to_the_owning_tenant(auth_client, db_session):
    from tests.test_brand_guard_api import _pro_profile
    client, tenant = auth_client
    pid = await _pro_profile(client, tenant, db_session)
    assert (await client.get(f"/brand-guard/profiles/{pid}/reference/screenshot")).status_code == 404            # none captured yet
    profile = await db_session.get(BrandProfile, uuid.UUID(pid))
    await bc.store_reference(db_session, profile=profile, shot_b64=b64(BRAND_PAGE), layout=REF["layout"], palette=REF["palette"])
    await db_session.commit()
    r = await client.get(f"/brand-guard/profiles/{pid}/reference/screenshot")
    assert r.status_code == 200 and r.content == BRAND_PAGE and r.headers["content-type"] == "image/png"
    assert r.headers["x-content-type-options"] == "nosniff" and "no-store" in r.headers["cache-control"] and "sandbox" in r.headers["content-security-policy"]
    assert (await client.get("/brand-guard/profiles/not-a-uuid/reference/screenshot")).status_code == 404
    assert (await client.get(f"/brand-guard/profiles/{uuid.uuid4()}/reference/screenshot")).status_code == 404
    from tests.test_brand_graph import _brand
    _, other = await _brand(db_session, name=f"other-{uuid.uuid4().hex[:6]}.co.za")
    await bc.store_reference(db_session, profile=other, shot_b64=b64(BRAND_PAGE), layout=None, palette=None)
    await db_session.commit()
    assert (await client.get(f"/brand-guard/profiles/{other.id}/reference/screenshot")).status_code == 404       # another tenant's brand


async def test_the_capture_endpoint_says_whether_a_reference_exists_to_compare_with(auth_client, db_session):
    from tests.test_brand_graph import cand as mk
    from tests.test_brand_guard_api import _pro_profile
    client, tenant = auth_client
    pid = await _pro_profile(client, tenant, db_session)
    profile = await db_session.get(BrandProfile, uuid.UUID(pid))
    c = mk(profile, "live.xyz", status="monitoring")
    db_session.add(c)
    await db_session.commit()
    await bc.store(db_session, job_id=None, cand=c, render=pp.clean_render(raw_render()))
    await db_session.commit()
    meta = (await client.get(f"/brand-guard/candidates/{c.id}/capture")).json()
    assert meta["reference_available"] is False and meta["profile_id"] == pid
    await bc.store_reference(db_session, profile=profile, shot_b64=b64(BRAND_PAGE), layout=None, palette=None)
    await db_session.commit()
    assert (await client.get(f"/brand-guard/candidates/{c.id}/capture")).json()["reference_available"] is True
