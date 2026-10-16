"""
Real, unauthenticated inbound webhooks from external providers — SendGrid's
signed Event Webhook today (Phishing Simulation roadmap Phase 17). No user
auth by design (SendGrid isn't a Sentinel user); the signed-payload check
is what stands in for auth here, matching phishing_track.py's own
"unauthenticated by design, verified another way" convention.
"""
from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.sendgrid_webhook_service import record_suppression_events, verify_signature

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/sendgrid/events")
async def receive_sendgrid_events(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_twilio_email_event_webhook_signature: str | None = Header(default=None),
    x_twilio_email_event_webhook_timestamp: str | None = Header(default=None),
):
    """SendGrid POSTs a JSON array of real delivery events here. An
    unverified or mis-signed payload is rejected outright — this never
    trusts an inbound event enough to suppress a real address on its say-so
    alone without the signature actually checking out."""
    raw_body = await request.body()
    if not verify_signature(raw_body, x_twilio_email_event_webhook_signature or "", x_twilio_email_event_webhook_timestamp or ""):
        return JSONResponse(status_code=401, content={"detail": "Invalid or missing webhook signature"})

    events = await request.json()
    if not isinstance(events, list):
        return JSONResponse(status_code=400, content={"detail": "Expected a JSON array of events"})

    suppressed_count = await record_suppression_events(db, events)
    return {"received": len(events), "suppressed": suppressed_count}
