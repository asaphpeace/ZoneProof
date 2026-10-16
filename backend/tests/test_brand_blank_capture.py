"""A render that comes back as one flat colour is not a screenshot of anything (found on the first real run: a request limit that was too low left the
picture white). It must never become the brand's reference picture, and it must not be counted as a screenshot or kept for 30 days."""
import base64

import pytest
from PIL import Image, ImageDraw
from sqlalchemy import select

from app.models import BrandPageCapture, BrandReferenceCapture
from app.services import brand_probe_analysis as pa
from app.services import brand_probe_queue as q
from app.services import brand_similarity as bs
from tests.test_brand_funnel_hooks import stage                                                         # noqa: F401
from tests.test_brand_render_data import _cand, _render_job, on, raw_render, render_on                  # noqa: F401  (fixtures)
from tests.test_brand_similarity import enc, page
from tests.test_brand_similarity_flow import _ref_job

def b64(b):
    return base64.b64encode(b).decode()


def flat(colour="white", size=(1280, 800), fmt="JPEG"):
    return enc(Image.new("RGB", size, colour), fmt)


def logo_on_white(w, h):
    im = Image.new("RGB", (1280, 800), "white")
    ImageDraw.Draw(im).rectangle((640 - w // 2, 400 - h // 2, 640 - w // 2 + w - 1, 400 - h // 2 + h - 1), fill=(30, 90, 200))
    return enc(im, "JPEG", quality=60)


def soft_gradient(darkest):
    im = Image.new("RGB", (1280, 800))
    d = ImageDraw.Draw(im)
    for x in range(1280):
        v = round(240 + (darkest - 240) * x / 1279)
        d.line((x, 0, x, 799), fill=(v, v, v))
    return enc(im, "PNG")


def real_page():
    return enc(page().convert("RGB"), "JPEG", quality=60)


def test_a_flat_picture_is_blank_in_any_colour_and_format_and_a_real_page_is_not():
    for raw in (flat("white"), flat("black"), flat("#1a3c8f"), flat("white", fmt="PNG"), flat("white", size=(300, 200))):
        assert bs.is_blank(raw) is True
    assert bs.is_blank(real_page()) is False


def test_the_limit_sits_between_a_speck_and_a_small_logo():
    # Measured with this function's own reduction: a 40x20 speck 0.3% of the pixels, a 100x50 logo 0.94%, a 160x80 logo 2.2%, a real page ~87%.
    assert bs.is_blank(logo_on_white(40, 20)) is True
    assert bs.is_blank(logo_on_white(100, 50)) is False
    assert bs.is_blank(logo_on_white(160, 80)) is False


def test_a_faint_gradient_is_blank_but_a_visible_one_is_not():
    # Up to 6 grey levels from the background is compression-level noise; a page that fades 8 levels is showing something.
    assert bs.is_blank(soft_gradient(236)) is True                      # 4 levels
    assert bs.is_blank(soft_gradient(232)) is False                     # 8 levels


def test_something_that_is_not_an_image_is_undecided_not_blank():
    for junk in (b"", b"<html>hello</html>", None, "text"):
        assert bs.is_blank(junk) is None


def test_a_blank_render_has_no_screenshot_hash_or_palette_and_is_flagged():
    blank = pa.analyse_render(raw_render(screenshot_b64=b64(flat())), host="live.xyz", official_domains=[], brand_words=["acme"])
    assert blank["blank"] is True and blank["has_screenshot"] is False and blank["layout"] is None and blank["palette"] is None
    good = pa.analyse_render(raw_render(screenshot_b64=b64(real_page())), host="live.xyz", official_domains=[], brand_words=["acme"])
    assert good["blank"] is False and good["has_screenshot"] is True and good["layout"]
    fake = pa.analyse_render(raw_render(), host="live.xyz", official_domains=[], brand_words=["acme"])                  # bytes that are not an image
    assert fake["blank"] is False and fake["has_screenshot"] is True


async def test_a_blank_picture_never_becomes_the_brands_reference(db_session, render_on):                # noqa: F811
    profile, _ = await _cand(db_session)
    job = await _ref_job(db_session, profile)
    assert await q.complete(db_session, job.id, {"ok": True, "render": raw_render(screenshot_b64=b64(flat()))}) == "ok"
    await db_session.refresh(job)
    assert job.status == "failed" and "blank" in job.error
    assert (await db_session.execute(select(BrandReferenceCapture))).scalars().all() == []
    ok = await _ref_job(db_session, profile)                                                       # and a later real render is accepted as usual
    await q.complete(db_session, ok.id, {"ok": True, "render": raw_render(screenshot_b64=b64(real_page()))})
    assert len((await db_session.execute(select(BrandReferenceCapture))).scalars().all()) == 1


async def test_a_blank_look_alike_render_keeps_its_text_but_not_its_picture_and_is_counted_as_blank(db_session, render_on):     # noqa: F811
    profile, row = await _cand(db_session)
    row.enrichment = {"probe": {"reachable": True, "forms": [], "similarity": {}}}
    await db_session.commit()
    job = await _render_job(db_session, profile, row)
    await q.complete(db_session, job.id, {"ok": True, "render": raw_render(screenshot_b64=b64(flat()))})
    cap = (await db_session.execute(select(BrandPageCapture))).scalar_one()
    assert cap.screenshot_enc is None and cap.screenshot_mime is None and cap.text_enc          # the words are still evidence; a white rectangle is not
    await db_session.refresh(row)
    assert row.enrichment["probe"]["rendered"]["blank"] is True and row.enrichment["probe"]["rendered"]["has_screenshot"] is False
    assert await stage(db_session, "render_done", profile.id) == (1, 0, {"blank": 1})
    good = await _render_job(db_session, profile, row)
    await q.complete(db_session, good.id, {"ok": True, "render": raw_render(screenshot_b64=b64(real_page()))})
    assert await stage(db_session, "render_done", profile.id) == (2, 1, {"blank": 1})
