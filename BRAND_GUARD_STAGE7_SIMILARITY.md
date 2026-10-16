# Brand Guard 7.4: visual, logo and wording similarity

Built 2026-10-09. Follows the plan's rule for this step: similarity is a **feature, never a verdict**. It adds evidence next to the other signals, can never confirm a look-alike on its own, and each piece is only as strong as it measured. Like the rest of Stage 7 it needs the worker and the renderer switch; nothing here makes a network request of its own.

## What it compares
| Feature | Look-alike side | Brand side | Method | Score weight |
|---|---|---|---|---|
| Icon | the favicon the light probe fetched | the favicon in the brand fingerprint | 64-bit difference hash, near = at most 10% of bits differ | **+8** (a byte-identical copy is the existing +12 line; the two never both fire) |
| Wording | the page's visible text (plain page or rendered) | hashed three-word runs of the brand's home page (kept in the fingerprint, no words stored) | share of the look-alike's three-word runs that also appear on the brand's page; needs 30+ runs each side | **+10** at 40% shared, **+14** at 70% |
| Page look | screenshot from the renderer | screenshot of the customer's own page, rendered the same way | 256-bit layout hash AND accent-colour overlap (12 hue bins) | **0**: shown, never scored |

Everything is "no comparison" rather than "different" when a piece is missing: no reference yet, too little text, a blank or all-grey picture, an unreadable image.

## What was measured, and what it means
Measured on **synthetic** material only (generated icons and generated bank-style pages rendered in Chromium, re-encoded, resized, blurred, cropped, brightened). Nobody has measured this on real South African phishing pages: that needs labelled screenshots, which is part of the data work that was reserved for last. Reproduce with `backend/brand_eval/similarity_synthetic.py`.

**Icons (64-bit hash).** 413 variants of the same logo (16 to 256 px, ICO, heavy JPEG) against 3,422 pairs of unrelated logos.
- Same logo: median distance 0.016, 90th percentile 0.047, worst 0.156. Unrelated: closest pair 0.172, median 0.422.
- Threshold 0.10 catches 98% of same-logo variants with **0 of 3,422** unrelated pairs falling under it. (At 0.20 it catches 100% but 0.23% of unrelated pairs fall under.)
- Adopted: 0.10, weight 8. Real icons are often simpler than the generated ones (a plain coloured square), so real-world false-near rates are probably higher than 0 and unknown.

**Whole-page screenshots: the layout hash alone does not survive.** 10 generated brand pages, each with a re-encoded/resized/cropped set (90), a clone (20), a "same layout, different brand" page (10) and every other brand's page (90).
- Same page re-encoded and the like: median distance 0.043. Clones: median 0.008. **Same layout, other brand: median 0.074, worst 0.125, as close as the clones.** Unrelated layouts: median 0.277.
- At any threshold that catches clones, 80 to 100% of the same-template other-brand pages are also "near". A layout hash is a template detector, not a clone detector: it would flag every bank login page that uses the same common layout.
- Adding the accent colours fixes that in this test: layout within 0.20 AND colour overlap at least 0.6 gave **0% false-near** on the same-template pages and on the others, but caught only 52% of re-encoded copies and 70% of clones (many generated pages have no strong accent colour, so no palette, so no comparison).
- The test is flattering to the colour check: the generated brands got random colours. Real banks do share blues and greens, and real clones are sometimes recoloured. So it stays at **weight 0**: the page look is shown in the drawer next to the customer's own page for a person to judge, but it never moves a score.

**Wording.** Tested with generated text: a copied page (with extra words appended) overlaps over 90%, an unrelated page under 5%, a half-copied one lands between. A long brand page is compared on the same slice of hashes as the stored sample, otherwise a full copy would look about 10% shared. Weaknesses that are not measured: the reference is the brand's **home page** only, so a cloned login page shares little wording with it (this feature finds cloned front pages, not cloned login screens); and boilerplate shared by many sites (cookie notices, "terms and privacy") adds some overlap, which is why the threshold is as high as 40%.

## Where the pieces live
- `app/services/brand_similarity.py`: all the pure comparison code. Images are size-checked from the header before decoding (25 megapixel cap, 1.2 MB cap), only JPEG, PNG, ICO, GIF, WEBP and BMP are opened, and any failure means "no result".
- Brand reference: `brand_fingerprint_service.build_fingerprint` now stores `fingerprint["similarity"]` (icon hash and hashed wording). **Existing brands need "rebuild" on the Brand profile page** to get it; until then icon and wording comparisons simply do not happen. It is not sent to the browser.
- Page reference: a new `ref` job renders the customer's own page through the same isolated renderer (same container, same limits), once per brand and again every 30 days (`BRAND_REFERENCE_REFRESH_DAYS`). It is the customer's own public page, so it is kept until replaced (encrypted, tenant-scoped) in `brand_reference_captures`. When a new reference arrives, look-alikes already rendered are re-compared and rescored.
- Evidence lines: `page_icon_lookalike`, `page_copies_wording`, `page_looks_like_brand` (page family; the last one weighs 0).
- Drawer: similarity lines in "What its web page showed", and, when both screenshots exist, "Your page" beside "This look-alike".

## What this does not do
- No VLM or model-based judgement. That belongs to Stage 6 and needs your decisions on provider, budget and what attacker-controlled content may be sent.
- No logo extraction from a page (only the favicon is compared) and no comparison against other brands' logos.
- No measurement on real phishing pages. Thresholds and weights are expert-set from the synthetic test above.
- Migration `d4f8b2c6e0a1` (applied to the dev database only). Probe jobs may now have no candidate (a `ref` job belongs to a brand).
