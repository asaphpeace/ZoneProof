"""The egress worker's API (plan step 7.1). Not a user API: callers prove themselves with an HMAC over the request (brand_probe_protocol), and the
key can do nothing but claim and complete probe jobs. While the kill switch is off every call is refused with 503 and the worker idles."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.rate_limit import limiter
from app.services import brand_probe_protocol, brand_probe_queue

router = APIRouter(prefix="/probe-worker", tags=["probe-worker"])


async def _authenticated_body(request: Request, limit: int = brand_probe_protocol.MAX_BODY_BYTES) -> bytes:
    if not brand_probe_queue.enabled():
        raise HTTPException(status_code=503, detail="Probing is switched off")
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail="Too large")
    body = await request.body()
    if len(body) > limit:
        raise HTTPException(status_code=413, detail="Too large")
    if not brand_probe_protocol.verify(settings.brand_probe_key, request.method, request.scope["path"], request.headers.get("x-probe-timestamp", ""), body, request.headers.get("x-probe-signature", "")):
        raise HTTPException(status_code=401, detail="Bad signature")
    return body


@router.post("/claim")
@limiter.limit("120/minute")
async def claim(request: Request, db: AsyncSession = Depends(get_db)):
    await _authenticated_body(request)
    job = await brand_probe_queue.claim(db)
    if job is None:
        return {"job": None}
    return {"job": {"id": str(job.id), "host": job.host, "kind": job.kind, "expires_at": job.expires_at.isoformat()}}


@router.post("/jobs/{job_id}/result", status_code=204)
@limiter.limit("120/minute")
async def result(request: Request, job_id: str, db: AsyncSession = Depends(get_db)):
    import json
    body = await _authenticated_body(request, brand_probe_protocol.MAX_RENDER_BODY_BYTES)     # a render result carries a screenshot
    try:
        jid = uuid.UUID(job_id)
        payload = json.loads(body or b"{}")
    except ValueError:
        raise HTTPException(status_code=422, detail="Bad request")
    outcome = await brand_probe_queue.complete(db, jid, payload.get("result") if isinstance(payload, dict) else None)
    if outcome == "unknown":
        raise HTTPException(status_code=404, detail="Unknown job")
    if outcome == "stale":
        raise HTTPException(status_code=409, detail="That job is not waiting for a result")
    if outcome == "disabled":
        raise HTTPException(status_code=503, detail="Probing is switched off")
    return Response(status_code=204)
