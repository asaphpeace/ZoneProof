"""Storage for what the sandboxed renderer captured (plan step 7.3): a screenshot and the page's visible text.

A live phishing page can show other victims' data and the brand's imagery, so a capture is treated as sensitive third-party content:
  - encrypted at rest (the same Fernet helper as other stored secrets),
  - served only to the tenant that owns the candidate, and only as an image or plain text,
  - deleted `brand_capture_retention_days` (30) after capture, unless the look-alike has become a case (confirmed or in takedown), because a
    takedown may need the screenshot as evidence. When the case closes, the capture is deleted on the next purge after its 30 days.
"""
from __future__ import annotations

import base64
import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import BrandCandidate, BrandPageCapture, BrandReferenceCapture
from app.services import crypto_service

log = logging.getLogger(__name__)
CASE_STATUSES = ("confirmed", "takedown")
KEEP_PER_CANDIDATE = 3


def _mime(raw: bytes) -> str | None:
    if raw.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    return None


async def store(db: AsyncSession, *, job_id, cand: BrandCandidate, render: dict, now: datetime | None = None) -> BrandPageCapture:
    """Keep one capture (already cleaned by brand_probe_protocol.clean_render) and drop this candidate's oldest ones beyond the last few."""
    now = now or datetime.now(timezone.utc)
    shot = render.get("screenshot_b64")
    mime = _mime(base64.b64decode(shot)) if shot else None
    cap = BrandPageCapture(
        id=uuid.uuid4(), tenant_id=cand.tenant_id, candidate_id=cand.id, job_id=job_id, captured_at=now,
        retain_until=now + timedelta(days=settings.brand_capture_retention_days),
        screenshot_enc=crypto_service.encrypt_secret(shot) if shot and mime else None, screenshot_mime=mime,
        text_enc=crypto_service.encrypt_secret(render["text"]) if render.get("text") else None,
        title=render.get("title"), final_url=render.get("final_url"), forms=render.get("forms") or [], nav_chain=render.get("nav_chain") or [],
        stats={"requests": render.get("requests"), "blocked": render.get("blocked"), "timed_out": bool(render.get("timed_out"))},
    )
    db.add(cap)
    await db.flush()
    older = (await db.execute(select(BrandPageCapture.id).where(BrandPageCapture.candidate_id == cand.id).order_by(BrandPageCapture.captured_at.desc()).offset(KEEP_PER_CANDIDATE))).scalars().all()
    if older:
        await db.execute(delete(BrandPageCapture).where(BrandPageCapture.id.in_(older)))
    return cap


async def latest(db: AsyncSession, tenant_id, candidate_id) -> BrandPageCapture | None:
    """The newest capture for a candidate, only if it belongs to this tenant and is still within retention (or the candidate is a case)."""
    now = datetime.now(timezone.utc)
    return (await db.execute(select(BrandPageCapture).join(BrandCandidate, BrandCandidate.id == BrandPageCapture.candidate_id).where(
        BrandPageCapture.tenant_id == tenant_id, BrandPageCapture.candidate_id == candidate_id,
        or_(BrandPageCapture.retain_until > now, BrandCandidate.status.in_(CASE_STATUSES)),
    ).order_by(BrandPageCapture.captured_at.desc()).limit(1))).scalar_one_or_none()


def screenshot_bytes(cap: BrandPageCapture) -> bytes | None:
    if not cap.screenshot_enc:
        return None
    try:
        raw = base64.b64decode(crypto_service.decrypt_secret(cap.screenshot_enc))
    except ValueError:
        return None
    return raw if _mime(raw) == cap.screenshot_mime else None


def page_text(cap: BrandPageCapture) -> str | None:
    if not cap.text_enc:
        return None
    try:
        return crypto_service.decrypt_secret(cap.text_enc)
    except ValueError:
        return None


async def store_reference(db: AsyncSession, *, profile, shot_b64: str, layout: str | None, palette: str | None, now: datetime | None = None) -> BrandReferenceCapture | None:
    """Keep (replace) the brand's own page as the reference. Only a real JPEG/PNG is stored."""
    now = now or datetime.now(timezone.utc)
    raw = base64.b64decode(shot_b64)
    mime = _mime(raw)
    if mime is None:
        return None
    row = (await db.execute(select(BrandReferenceCapture).where(BrandReferenceCapture.profile_id == profile.id))).scalar_one_or_none()
    if row is None:
        row = BrandReferenceCapture(id=uuid.uuid4(), tenant_id=profile.tenant_id, profile_id=profile.id)
        db.add(row)
    row.captured_at, row.screenshot_enc, row.screenshot_mime, row.layout_hash, row.palette = now, crypto_service.encrypt_secret(shot_b64), mime, layout, palette
    await db.flush()
    return row


async def reference_for(db: AsyncSession, tenant_id, profile_id) -> BrandReferenceCapture | None:
    return (await db.execute(select(BrandReferenceCapture).where(BrandReferenceCapture.tenant_id == tenant_id, BrandReferenceCapture.profile_id == profile_id))).scalar_one_or_none()


def reference_bytes(row: BrandReferenceCapture) -> bytes | None:
    return screenshot_bytes(row)           # same layout of fields: encrypted base64 plus a mime that must match the signature


async def purge(db: AsyncSession, now: datetime | None = None) -> int:
    """Delete captures past retention, except those of candidates that are cases. Returns how many were deleted."""
    now = now or datetime.now(timezone.utc)
    keep = select(BrandCandidate.id).where(BrandCandidate.status.in_(CASE_STATUSES))
    res = await db.execute(delete(BrandPageCapture).where(BrandPageCapture.retain_until < now, BrandPageCapture.candidate_id.not_in(keep)))
    await db.commit()
    n = res.rowcount or 0
    if n:
        log.info("Brand Guard: purged %d expired page capture(s)", n)
    return n
