"""Reproduces the synthetic measurement behind BRAND_GUARD_STAGE7_SIMILARITY.md: how the icon, layout and accent-colour hashes behave on generated icons and generated pages (rendered in a local Chromium; no network, no real site).

    python -m brand_eval.similarity_synthetic        (from the backend folder; needs Pillow and Playwright with Chromium installed)

The numbers are SYNTHETIC evidence only. They say how the methods behave on controlled variants, not how they perform on real phishing pages."""

import io
import os
import random
import statistics
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter
from playwright.sync_api import sync_playwright

from app.services import brand_similarity as bs

R = random.Random(7)


def hexcolor():
    return "#%02x%02x%02x" % (R.randint(0, 255), R.randint(0, 255), R.randint(0, 255))


def page(brand: str, c1: str, c2: str, layout: int, hero: str, variant: int = 0) -> str:
    login = f'<div style="background:#fff;border-radius:10px;padding:28px;width:340px;box-shadow:0 2px 12px #0003"><h3 style="margin:0 0 14px">Sign in to {brand}</h3><input placeholder="Email" style="width:100%;padding:10px;margin-bottom:10px"><input type=password placeholder="Password" style="width:100%;padding:10px;margin-bottom:14px"><button style="background:{c2};color:#fff;border:0;padding:10px 20px;width:100%">Sign in</button></div>'
    logo = f'<div style="width:{120 + variant}px;height:38px;background:{c2};border-radius:6px;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700">{brand}</div>'
    if layout == 0:        # header bar, hero left, login right
        body = f'<div style="background:{c1};padding:16px 40px;display:flex;justify-content:space-between">{logo}<span style="color:#fff">Help · Contact</span></div><div style="display:flex;padding:60px 80px;gap:80px;background:#f3f5f9;height:640px"><div style="flex:1"><h1 style="font-size:44px;margin:0 0 20px">{hero}</h1><p style="font-size:18px;color:#444">Fast, secure and simple banking for every South African. Manage your money anywhere, any time.</p></div>{login}</div>'
    elif layout == 1:      # centered login on dark
        body = f'<div style="background:{c1};height:800px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:24px">{logo}{login}</div>'
    elif layout == 2:      # sidebar + content
        body = f'<div style="display:flex;height:800px"><div style="width:260px;background:{c1};padding:24px">{logo}<p style="color:#fff">Accounts<br>Cards<br>Loans<br>Insurance</p></div><div style="flex:1;padding:50px;background:#fff"><h1>{hero}</h1><div style="display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-top:30px">' + "".join(f'<div style="background:{c2};height:150px;border-radius:10px;opacity:.{5 + i}"></div>' for i in range(3)) + '</div></div></div>'
    else:                  # long text page
        body = f'<div style="padding:40px 120px;background:#fff">{logo}<h1>{hero}</h1>' + "".join(f"<p style='font-size:16px;color:#333'>{hero} paragraph {i}. Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor.</p>" for i in range(14)) + "</div>"
    return f'<html><body style="margin:0;font-family:Arial,sans-serif">{body}</body></html>'


def reencode(raw: bytes, q: int) -> bytes:
    im = Image.open(io.BytesIO(raw)).convert("RGB")
    out = io.BytesIO()
    im.save(out, "JPEG", quality=q)
    return out.getvalue()


def variants(raw: bytes):
    im = Image.open(io.BytesIO(raw)).convert("RGB")
    w, h = im.size
    def jpg(i, q=60):
        o = io.BytesIO(); i.save(o, "JPEG", quality=q); return o.getvalue()
    yield "recompress q30", jpg(im, 30)
    yield "recompress q90", jpg(im, 90)
    yield "resize 0.5", jpg(im.resize((w // 2, h // 2)))
    yield "resize 1.5", jpg(im.resize((int(w * 1.5), int(h * 1.5))))
    yield "blur", jpg(im.filter(ImageFilter.GaussianBlur(1.5)))
    yield "brightness +20%", jpg(ImageEnhance.Brightness(im).enhance(1.2))
    yield "brightness -20%", jpg(ImageEnhance.Brightness(im).enhance(0.8))
    yield "crop 5%", jpg(im.crop((int(w * .05), int(h * .05), w, h)).resize((w, h)))
    yield "crop 10%", jpg(im.crop((int(w * .1), int(h * .1), w, h)).resize((w, h)))


def stats(name, xs):
    xs = sorted(xs)
    print(f"  {name:34s} n={len(xs):3d} min={xs[0]:.3f} median={statistics.median(xs):.3f} p90={xs[int(len(xs) * .9) - 1]:.3f} max={xs[-1]:.3f}")


shots = {}
with sync_playwright() as p:
    b = p.chromium.launch(args=["--no-sandbox"])
    pg = b.new_page(viewport={"width": 1280, "height": 800})
    heroes = ["Bank smarter today", "Your money, your way", "Insure what matters", "Pay anywhere", "Welcome back", "Simple finance"]
    names = ["Acme", "Nedora", "Capewell", "Firstline", "Sablebank", "Zuluva", "Mapleton", "Karoo Pay", "Vaalfin", "Protea"]
    brands = []
    for n in names:
        brands.append(dict(name=n, c1=hexcolor(), c2=hexcolor(), layout=R.choice([0, 1, 2, 3]), hero=R.choice(heroes)))
    def shot(html):
        pg.set_content(html)
        return pg.screenshot(type="jpeg", quality=60)
    for br in brands:
        br["raw"] = shot(page(br["name"], br["c1"], br["c2"], br["layout"], br["hero"]))
        br["clone"] = shot(page(br["name"], br["c1"], br["c2"], br["layout"], br["hero"], variant=6))      # a clone: same design, slightly different logo width
        br["clone_text"] = shot(page(br["name"].lower() + "-secure", br["c1"], br["c2"], br["layout"], br["hero"] + " now"))   # a clone with the name tweaked
        br["samelayout_diffcolour"] = shot(page(br["name"] + "x", hexcolor(), hexcolor(), br["layout"], R.choice(heroes)))     # hard negative: same layout, other brand
    b.close()

print("PAGE screenshots, dHash 256 bits (distance = share of differing bits)")
same, clone, vclones, hard, other = [], [], [], [], []
for br in brands:
    h0 = bs.dhash(br["raw"], 16)
    print("   bits set:", bin(int(h0,16)).count("1"), br["name"], br["layout"])
    clone.append(bs.distance(h0, bs.dhash(br["clone"], 16)))
    clone.append(bs.distance(h0, bs.dhash(br["clone_text"], 16)))
    hard.append(bs.distance(h0, bs.dhash(br["samelayout_diffcolour"], 16)))
    for _, v in variants(br["raw"]):
        vclones.append(bs.distance(h0, bs.dhash(v, 16)))
    for o in brands:
        if o is not br:
            other.append(bs.distance(h0, bs.dhash(o["raw"], 16)))
stats("re-encoded/resized/cropped same page", vclones)
stats("clone (logo/name tweaked)", clone)
stats("HARD NEGATIVE same layout, other brand", hard)
stats("other brand pages (any layout)", other)
for t in (0.10, 0.12, 0.14, 0.16, 0.18, 0.20, 0.25):
    print(f"  threshold {t:.2f}: catches {sum(x <= t for x in vclones + clone) / len(vclones + clone):.0%} of same/clone, false-near on hard negatives {sum(x <= t for x in hard) / len(hard):.0%}, on others {sum(x <= t for x in other) / len(other):.0%}")


print("PAGE layout dHash + accent palette (combined)")
def pal(x): return bs.palette(x)
rows = {"same/variants": [], "clone": [], "HARD same layout other brand": [], "other pages": []}
for br in brands:
    h0, p0 = bs.dhash(br["raw"], 16), pal(br["raw"])
    for _, v in variants(br["raw"]):
        rows["same/variants"].append((bs.distance(h0, bs.dhash(v, 16)), bs.palette_overlap(p0, pal(v))))
    for k in ("clone", "clone_text"):
        rows["clone"].append((bs.distance(h0, bs.dhash(br[k], 16)), bs.palette_overlap(p0, pal(br[k]))))
    rows["HARD same layout other brand"].append((bs.distance(h0, bs.dhash(br["samelayout_diffcolour"], 16)), bs.palette_overlap(p0, pal(br["samelayout_diffcolour"]))))
    for o in brands:
        if o is not br:
            rows["other pages"].append((bs.distance(h0, bs.dhash(o["raw"], 16)), bs.palette_overlap(p0, pal(o["raw"]))))
for k, v in rows.items():
    po = [x[1] for x in v if x[1] is not None]
    print(f"  {k:30s} palette overlap: n={len(po)} min={min(po):.2f} median={statistics.median(po):.2f} max={max(po):.2f}  (none={sum(x[1] is None for x in v)})")
for dt, pt in ((0.16, 0.6), (0.20, 0.6), (0.20, 0.7), (0.25, 0.7), (0.25, 0.8)):
    def hit(v): return sum(1 for d, p in v if d is not None and d <= dt and p is not None and p >= pt) / len(v)
    print(f"  layout<={dt:.2f} AND palette>={pt:.1f}: same/variants {hit(rows['same/variants']):.0%}, clones {hit(rows['clone']):.0%}, HARD negatives {hit(rows['HARD same layout other brand']):.0%}, others {hit(rows['other pages']):.0%}")

# ICONS: synthetic logos 64x64
def logo(seed, size=64):
    r = random.Random(seed)
    im = Image.new("RGBA", (size, size), (255, 255, 255, 0) if seed % 2 else (255, 255, 255, 255))
    d = ImageDraw.Draw(im)
    for _ in range(r.randint(2, 5)):
        c = tuple(r.randint(0, 255) for _ in range(3)) + (255,)
        x0, y0 = r.randint(0, size - 20), r.randint(0, size - 20)
        x1, y1 = x0 + r.randint(10, size - x0), y0 + r.randint(10, size - y0)
        (d.ellipse if r.random() < .5 else d.rectangle)((x0, y0, x1, y1), fill=c)
    return im


def png(im, size=None):
    if size:
        im = im.resize((size, size), Image.Resampling.LANCZOS)
    o = io.BytesIO(); im.save(o, "PNG"); return o.getvalue()


def ico(im):
    o = io.BytesIO(); im.convert("RGBA").save(o, "ICO", sizes=[(16, 16), (32, 32)]); return o.getvalue()


print("\nICONS, dHash 64 bits")
logos = [logo(s) for s in range(60)]
ic_same, ic_other = [], []
for i, lg in enumerate(logos):
    h0 = bs.dhash(png(lg), 8)
    if not bs.informative(h0):
        continue
    for size in (16, 32, 48, 128, 256):
        ic_same.append(bs.distance(h0, bs.dhash(png(lg, size), 8)))
    ic_same.append(bs.distance(h0, bs.dhash(ico(lg), 8)))
    ic_same.append(bs.distance(h0, bs.dhash(reencode(png(lg), 40), 8)))
    for j, o in enumerate(logos):
        if j != i:
            ho = bs.dhash(png(o), 8)
            if bs.informative(ho):
                ic_other.append(bs.distance(h0, ho))
stats("same logo at other sizes/format", ic_same)
stats("unrelated logos", ic_other)
for t in (0.06, 0.08, 0.10, 0.12, 0.15, 0.20):
    print(f"  threshold {t:.2f}: catches {sum(x <= t for x in ic_same) / len(ic_same):.0%} of same logo, false-near on unrelated {sum(x <= t for x in ic_other) / len(ic_other):.2%}")

print("\nINFORMATIVE guard: blank white page ->", bs.informative(bs.dhash(png(Image.new('RGB', (200, 200), 'white')), 8)), "| 2 blank pages comparable ->", bs.compare_hashes(bs.dhash(png(Image.new('RGB', (200, 200), 'white')), 8), bs.dhash(png(Image.new('RGB', (200, 200), 'white')), 8), .1))
