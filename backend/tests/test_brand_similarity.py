"""Step 7.4: image and wording similarity. Pure, so everything is built from synthetic pictures made here."""
import io
import time

import pytest
from PIL import Image, ImageDraw

from app.services import brand_similarity as bs


def logo(seed=1, size=64, transparent=False):
    import random
    r = random.Random(seed)
    im = Image.new("RGBA", (size, size), (255, 255, 255, 0) if transparent else (255, 255, 255, 255))
    d = ImageDraw.Draw(im)
    for _ in range(4):
        c = tuple(r.randint(0, 255) for _ in range(3)) + (255,)
        x0, y0 = r.randint(0, size - 24), r.randint(0, size - 24)
        (d.ellipse if r.random() < .5 else d.rectangle)((x0, y0, x0 + r.randint(12, size - x0), y0 + r.randint(12, size - y0)), fill=c)
    return im


def enc(im, fmt="PNG", **kw):
    o = io.BytesIO()
    im.save(o, fmt, **kw)
    return o.getvalue()


def page(c1="#1a3c8f", c2="#e0a000", layout=0):
    im = Image.new("RGB", (640, 400), "#f4f5f8")
    d = ImageDraw.Draw(im)
    d.rectangle((0, 0, 640, 50), fill=c1)
    d.rectangle((30, 8, 150, 42), fill=c2)
    if layout == 0:
        d.rectangle((400, 110, 600, 330), fill="white", outline="#999")
        d.rectangle((420, 200, 580, 225), fill="#ddd")
        d.rectangle((420, 270, 580, 300), fill=c2)
        d.rectangle((40, 120, 330, 160), fill="#333")
    else:
        d.rectangle((0, 50, 160, 400), fill=c1)
        for i in range(3):
            d.rectangle((200 + i * 140, 120, 310 + i * 140, 260), fill=c2)
    return im


# ── icons ──────────────────────────────────────────────────────────────────

def test_the_same_icon_re_sized_re_encoded_or_as_ico_hashes_nearly_the_same_and_an_unrelated_one_does_not():
    base = bs.dhash(enc(logo(3)), 8)
    for variant in (enc(logo(3).resize((16, 16), Image.Resampling.LANCZOS)), enc(logo(3).resize((200, 200), Image.Resampling.LANCZOS)),
                    enc(logo(3).convert("RGB"), "JPEG", quality=40), enc(logo(3), "ICO", sizes=[(32, 32)])):
        assert bs.distance(base, bs.dhash(variant, 8)) <= bs.ICON_NEAR, bs.distance(base, bs.dhash(variant, 8))
    assert bs.distance(base, bs.dhash(enc(logo(4)), 8)) > 0.2


def test_a_transparent_logo_is_flattened_onto_white_so_it_does_not_hash_as_black():
    assert bs.dhash(enc(logo(5, transparent=True)), 8) == bs.dhash(enc(logo(5)), 8)
    im = Image.new("RGBA", (64, 64), (0, 0, 0, 0))                                 # transparent, but black underneath: must not hash as a black square
    ImageDraw.Draw(im).ellipse((12, 12, 52, 52), fill=(200, 30, 30, 255))
    flat = Image.new("RGBA", (64, 64), (255, 255, 255, 255))
    flat.alpha_composite(im)
    assert bs.dhash(enc(im), 8) == bs.dhash(enc(flat), 8)


@pytest.mark.parametrize("raw", [None, b"", b"not an image", b"\x89PNG\r\n\x1a\n" + b"x" * 40, b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>", "text", 5, b"GIF89a" + b"\x00" * 10])
def test_anything_that_is_not_a_usable_image_gives_no_hash_and_never_raises(raw):
    assert bs.dhash(raw, 8) is None and bs.palette(raw) is None


def test_oversized_and_decompression_bomb_images_are_refused_before_decoding():
    assert bs.dhash(b"\xff\xd8\xff" + b"x" * (bs.MAX_IMAGE_BYTES + 1), 8) is None
    import random
    r = random.Random(1)
    noisy = Image.frombytes("RGB", (700, 700), bytes(r.getrandbits(8) for _ in range(700 * 700 * 3)))
    big = enc(noisy)                                                               # a valid image that is simply too many bytes
    assert len(big) > bs.MAX_IMAGE_BYTES and bs.dhash(big, 8) is None and bs.palette(big) is None
    assert bs.dhash(enc(noisy.resize((200, 200))), 8) is not None                  # the same picture, small enough, is fine
    bomb = enc(Image.new("1", (6000, 6000)), "PNG", optimize=True)         # tiny file, 36 million pixels
    assert len(bomb) < bs.MAX_IMAGE_BYTES
    started = time.monotonic()
    assert bs.dhash(bomb, 8) is None and bs.palette(bomb) is None
    assert time.monotonic() - started < 1.0


def test_only_the_expected_picture_formats_are_opened():
    assert bs.dhash(enc(logo(2), "PNG"), 8) and bs.dhash(enc(logo(2).convert("RGB"), "JPEG"), 8) and bs.dhash(enc(logo(2), "GIF"), 8) and bs.dhash(enc(logo(2), "WEBP"), 8)
    assert bs.dhash(enc(logo(2).convert("RGB"), "TIFF"), 8) is None and bs.dhash(enc(logo(2).convert("RGB"), "PPM"), 8) is None


# ── hashes ─────────────────────────────────────────────────────────────────

def test_blank_and_uniform_pictures_carry_no_signal_so_two_blank_pages_never_match():
    blank = bs.dhash(enc(Image.new("RGB", (300, 200), "white")), 16)
    assert blank is not None and not bs.informative(blank)
    assert bs.compare_hashes(blank, blank, 0.5) is None
    assert bs.compare_hashes(blank, bs.dhash(enc(page()), 16), 0.5) is None


def test_compare_hashes_reports_distance_and_whether_it_is_near_and_rejects_malformed_or_mismatched_hashes():
    a = bs.dhash(enc(page()), 16)
    assert bs.compare_hashes(a, a, 0.1) == {"distance": 0.0, "similar": True}
    far = bs.compare_hashes(a, bs.dhash(enc(page(layout=1)), 16), 0.05)
    assert far["similar"] is False and far["distance"] > 0.05
    for bad in (None, "", "zz", "g" * 16, 5, "a" * 65):
        assert bs.distance(bad, a) is None and not bs.informative(bad) and bs.hex_bits(bad) is None
    assert bs.distance(a, bs.dhash(enc(page()), 8)) is None                      # a 256-bit and a 64-bit hash are not comparable


def test_hash_sizes_and_threshold_boundaries():
    assert len(bs.dhash(enc(page()), 8)) == 16 and len(bs.dhash(enc(page()), 16)) == 64
    assert bs.compare_hashes("ffffffffffff0000", "ffffffffffff0000", 0.0)["similar"] is True
    one = "ffffffffffff0001"
    assert bs.compare_hashes("ffffffffffff0000", one, 1 / 64)["similar"] is True and bs.compare_hashes("ffffffffffff0000", one, 1 / 64 - 0.001)["similar"] is False


# ── page screenshots: layout AND accent colours ────────────────────────────

def test_a_page_is_similar_only_when_layout_and_accent_colours_both_match():
    brand = page()
    lb, pb = bs.dhash(enc(brand), 16), bs.palette(enc(brand))
    clone = enc(brand.convert("RGB"), "JPEG", quality=60)
    same = bs.compare_pages(lb, pb, bs.dhash(clone, 16), bs.palette(clone))
    assert same["similar"] is True and same["palette"] >= bs.PALETTE_SAME
    template = page(c1="#1a8f3c", c2="#8f1a5e")                                  # same layout, different brand colours
    other = bs.compare_pages(lb, pb, bs.dhash(enc(template), 16), bs.palette(enc(template)))
    assert other is not None and other["similar"] is False and other["layout"] <= bs.VISUAL_NEAR and other["palette"] < bs.PALETTE_SAME
    diff_layout = bs.compare_pages(lb, pb, bs.dhash(enc(page(layout=1)), 16), bs.palette(enc(page(layout=1))))
    assert diff_layout["similar"] is False


def test_a_page_without_accent_colours_has_no_palette_so_no_comparison_is_made():
    grey = Image.new("RGB", (640, 400), "#eeeeee")
    ImageDraw.Draw(grey).rectangle((100, 100, 400, 300), fill="#333333")
    assert bs.palette(enc(grey)) is None
    assert bs.compare_pages(bs.dhash(enc(grey), 16), None, bs.dhash(enc(grey), 16), None) is None
    assert bs.palette_overlap("00" * 12, "00" * 12) is None
    for bad in (None, "", "zz" * 12, "ab" * 5, 5):
        assert bs.palette_overlap(bad, "ab" * 12) is None


def test_palette_is_stable_under_recompression_and_overlap_is_symmetric():
    p = bs.palette(enc(page()))
    q = bs.palette(enc(page().convert("RGB"), "JPEG", quality=30))
    assert bs.palette_overlap(p, q) > 0.9 and bs.palette_overlap(p, q) == bs.palette_overlap(q, p)
    assert bs.palette_overlap(p, p) == 1.0 and len(p) == 24


# ── wording ────────────────────────────────────────────────────────────────

HOME = " ".join(f"word{i % 97} alpha{i % 53} beta{i % 31}" for i in range(400))


def test_shingles_are_deterministic_sorted_capped_distinct_and_survive_garbage():
    s = bs.shingles(HOME)
    assert s == bs.shingles(HOME) and s == sorted(s) and len(s) == len(set(s)) and all(len(x) == 8 for x in s)
    assert len(bs.shingles(HOME, cap=10)) == 10 and bs.shingles(HOME, cap=10) == s[:10]
    assert bs.shingles(None) == [] and bs.shingles(5) == [] and bs.shingles("") == [] and bs.shingles("a b") == [] and bs.shingles("\x00" * 100) == []
    assert bs.shingles("x" * 500_000) is not None


def test_a_page_that_reuses_the_brands_wording_overlaps_and_an_unrelated_one_does_not():
    brand = bs.shingles(HOME)
    copy = bs.wording_overlap(HOME + " extra login words appended to the end of the cloned page", brand)
    assert copy["shared"] >= 0.9 and copy["n"] >= bs.MIN_SHINGLES
    unrelated = bs.wording_overlap(" ".join(f"zebra{i} quartz{i % 7} lemon{i % 11}" for i in range(300)), brand)
    assert unrelated["shared"] < 0.05
    half = bs.wording_overlap(HOME[: len(HOME) // 2] + " " + " ".join(f"other{i} thing{i % 5} here{i % 9}" for i in range(120)), brand)
    assert 0.2 < half["shared"] < 0.8


def test_too_little_text_on_either_side_means_no_comparison_not_a_match():
    brand = bs.shingles(HOME)
    assert bs.wording_overlap("sign in to your account", brand) is None
    assert bs.wording_overlap(HOME, bs.shingles("only a few words here")) is None
    assert bs.wording_overlap(HOME, None) is None and bs.wording_overlap(HOME, []) is None and bs.wording_overlap(None, brand) is None


def test_a_long_brand_page_is_compared_on_the_same_slice_so_a_full_copy_still_overlaps_fully():
    long_text = " ".join(f"term{i} phrase{i * 7 % 1013} item{i * 13 % 997}" for i in range(3000))
    brand = bs.shingles(long_text)
    assert len(brand) == bs.MAX_REFERENCE_SHINGLES
    assert bs.wording_overlap(long_text, brand)["shared"] > 0.99          # without the slice rule this would be about 0.1
