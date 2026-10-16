"""Visual and wording similarity between a look-alike's page and the customer's real brand (plan step 7.4).

These are FEATURES, never verdicts. A near-identical icon, a page that reuses the brand's wording, or a screenshot that looks like the brand's own
page are signs of impersonation, but each has innocent explanations (a reseller using a supplied logo, a licensed template, two plain white login
pages), so they only ever add modest evidence next to the other signals and are never enough on their own.

Everything here is pure and defensive about its input: images come from hosts an attacker controls, so they are size-checked before they are
decoded, only a fixed set of formats is opened, and a failure of any kind means "no result", never an exception.

Methods (deliberately simple and explainable; no model, no network):
  - difference hash (dHash): shrink to grayscale, record whether each pixel is brighter than its right neighbour. Robust to resizing, recompression
    and small colour changes; two unrelated pictures differ in about half the bits. 64 bits for icons, 256 bits for screenshots.
  - an "informative" guard: an almost uniform picture (a blank page, a single colour) hashes to nearly all zeros and would "match" any other blank
    picture, so a hash with too few or too many set bits is treated as having no signal.
  - wording: the page's visible text is cut into overlapping three-word runs ("shingles"), hashed to 32 bits; the result is the share of the
    look-alike's runs that also appear on the customer's own page.

The thresholds are expert-set from how these methods behave on synthetic variants (see BRAND_GUARD_STAGE7_SIMILARITY.md); nobody has measured them
on real South African phishing pages, and they are labelled that way wherever they are shown.
"""
from __future__ import annotations

import hashlib
import io
import re

try:                                                    # Pillow is already a dependency (qrcode[pil]); without it image features simply do not exist
    from PIL import Image
except Exception:                                       # pragma: no cover
    Image = None

MAX_IMAGE_BYTES = 1_200_000
MAX_PIXELS = 25_000_000
_FORMATS = ("JPEG", "PNG", "ICO", "GIF", "WEBP", "BMP")
ICON_BITS = 64
PAGE_BITS = 256

# Expert-set thresholds (assumptions, not measurements on real phishing pages).
ICON_NEAR = 0.10              # at most ~6 of 64 bits differ (synthetic icons: 98% of re-sized/re-encoded copies, 0 of 3,422 unrelated pairs)
VISUAL_NEAR = 0.20            # layout hash: at most ~51 of 256 bits differ ...
PALETTE_SAME = 0.60           # ... AND the accent colours overlap this much (layout alone cannot tell a clone from the same template)
MIN_INFO, MAX_INFO = 0.03, 0.97       # share of set bits outside which a hash carries no signal (a blank page hashes to nothing)
MIN_SHINGLES = 30             # fewer distinct three-word runs than this is too little text to compare
WORDING_COPY = 0.40           # share of the look-alike's wording found on the real page
WORDING_STRONG = 0.70
MAX_REFERENCE_SHINGLES = 800


def _open(raw: bytes):
    """A decoded Pillow image, or None. The pixel count is checked from the header before anything is decoded."""
    if Image is None or not isinstance(raw, (bytes, bytearray)) or not raw or len(raw) > MAX_IMAGE_BYTES:
        return None
    try:
        im = Image.open(io.BytesIO(bytes(raw)))
        if im.format not in _FORMATS or im.width * im.height > MAX_PIXELS or im.width < 1 or im.height < 1:
            return None
        im.load()
        return im
    except Exception:                                   # truncated, hostile, or not an image at all
        return None


def _gray(im, size: tuple[int, int]):
    """Grayscale at `size`, with transparency flattened onto white (a transparent logo would otherwise hash as black)."""
    if im.mode in ("RGBA", "LA", "P"):
        im = im.convert("RGBA")
        bg = Image.new("RGBA", im.size, (255, 255, 255, 255))
        bg.alpha_composite(im)
        im = bg
    return im.convert("L").resize(size, Image.Resampling.LANCZOS)


def dhash(raw: bytes, side: int = 8) -> str | None:
    """Difference hash as hex (side*side bits), or None when the bytes are not a usable image."""
    im = _open(raw)
    if im is None:
        return None
    try:
        px = list(_gray(im, (side + 1, side)).getdata())
    except Exception:
        return None
    bits = 0
    for row in range(side):
        for col in range(side):
            bits = (bits << 1) | (1 if px[row * (side + 1) + col] > px[row * (side + 1) + col + 1] else 0)
    return format(bits, "x").zfill(side * side // 4)


_HUE_BINS = 12


def palette(raw: bytes) -> str | None:
    """The page's accent colours as 12 hue bins (2 hex characters each: the share of pixels, in 0.25% steps, that are clearly coloured, i.e.
    neither grey, white nor black). None when there are almost no coloured pixels, so a plain black-and-white page has no palette."""
    im = _open(raw)
    if im is None:
        return None
    try:
        small = im.convert("RGB").resize((80, 50), Image.Resampling.BOX).convert("HSV")
        data = list(small.getdata())
    except Exception:
        return None
    bins = [0] * _HUE_BINS
    for h, s, v in data:
        if s >= 90 and 50 <= v <= 245:                  # saturated, and neither near-black nor blown out
            bins[min(_HUE_BINS - 1, h * _HUE_BINS // 256)] += 1
    total = len(data)
    if sum(bins) / total < 0.01:
        return None
    return "".join(format(min(255, round(b / total * 400)), "02x") for b in bins)


def palette_overlap(a: str | None, b: str | None) -> float | None:
    """How much of the two pages' accent colouring is the same hue (1 identical, 0 nothing in common). None if either has no palette."""
    if not (isinstance(a, str) and isinstance(b, str) and len(a) == len(b) == _HUE_BINS * 2 and re.fullmatch(r"[0-9a-f]+", a + b)):
        return None
    va = [int(a[i:i + 2], 16) for i in range(0, len(a), 2)]
    vb = [int(b[i:i + 2], 16) for i in range(0, len(b), 2)]
    top = max(sum(va), sum(vb))
    return None if top == 0 else sum(min(x, y) for x, y in zip(va, vb)) / top


def hex_bits(h: str | None) -> int | None:
    if not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{1,64}", h):
        return None
    return len(h) * 4


BLANK_SHARE = 0.005          # measured: a blank render 0.0000, a 40x20 speck 0.003, a 100x50 logo alone on white 0.009, a real home page ~0.87


def is_blank(raw: bytes) -> bool | None:
    """True when the picture is one flat colour (a page whose styles or images never arrived, or a genuinely empty page): fewer than 0.5% of
    the pixels, on a 64x40 reduction, differ noticeably from the most common grey. None when the bytes are not a usable image."""
    im = _open(raw)
    if im is None:
        return None
    try:
        px = list(_gray(im, (64, 40)).getdata())
    except Exception:
        return None
    background = max(set(px), key=px.count)
    return sum(1 for p in px if abs(p - background) > 6) / len(px) < BLANK_SHARE


def informative(h: str | None) -> bool:
    """False for a hash that is nearly all zeros or all ones: a blank or uniform picture, which would match any other."""
    n = hex_bits(h)
    if not n:
        return False
    share = bin(int(h, 16)).count("1") / n
    return MIN_INFO <= share <= MAX_INFO


def distance(a: str | None, b: str | None) -> float | None:
    """Share of differing bits (0 identical, about 0.5 unrelated). None when either side is missing, malformed or of a different size."""
    na, nb = hex_bits(a), hex_bits(b)
    if not na or na != nb:
        return None
    return bin(int(a, 16) ^ int(b, 16)).count("1") / na


def compare_hashes(a: str | None, b: str | None, near: float) -> dict | None:
    """{distance, similar} when both hashes carry signal, else None (so a blank page never produces a comparison)."""
    if not (informative(a) and informative(b)):
        return None
    d = distance(a, b)
    return None if d is None else {"distance": round(d, 3), "similar": d <= near}


def compare_pages(layout_a: str | None, palette_a: str | None, layout_b: str | None, palette_b: str | None) -> dict | None:
    """Two screenshots: similar only when the layout hash is close AND the accent colours match. None when either lacks a usable layout
    hash or a palette, so "no comparison" is never reported as "different"."""
    lay = compare_hashes(layout_a, layout_b, VISUAL_NEAR)
    pal = palette_overlap(palette_a, palette_b)
    if lay is None or pal is None:
        return None
    return {"layout": lay["distance"], "palette": round(pal, 2), "similar": bool(lay["similar"] and pal >= PALETTE_SAME)}


_TOKEN = re.compile(r"[a-z0-9]{2,}")


def shingles(text: str | None, cap: int = MAX_REFERENCE_SHINGLES, k: int = 3) -> list[str]:
    """Distinct hashed k-word runs of a page's text (8 hex characters each), at most `cap`, chosen deterministically (smallest hashes first)."""
    if not isinstance(text, str):
        return []
    words = _TOKEN.findall(text[:60_000].lower())[:12_000]
    seen: set[str] = set()
    for i in range(len(words) - k + 1):
        seen.add(hashlib.blake2b(" ".join(words[i:i + k]).encode(), digest_size=4).hexdigest())
    return sorted(seen)[:cap]


def wording_overlap(candidate_text: str | None, brand_shingles: list[str] | None) -> dict | None:
    """The share of the look-alike's wording that also appears on the real page. None when either side has too little text to compare."""
    if not brand_shingles or len(brand_shingles) < MIN_SHINGLES:
        return None
    cand = shingles(candidate_text, cap=10_000)
    if len(brand_shingles) >= MAX_REFERENCE_SHINGLES:
        # The stored reference is the smallest hashes of a larger page: look at the same slice of the look-alike's runs, or a long brand
        # page would make every comparison look smaller than it is.
        cand = [s for s in cand if s <= brand_shingles[-1]]
    if len(cand) < MIN_SHINGLES:
        return None
    brand = set(brand_shingles)
    shared = sum(1 for s in cand if s in brand) / len(cand)
    return {"shared": round(shared, 3), "n": len(cand)}
