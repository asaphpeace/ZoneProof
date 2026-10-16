"""
Real bounce/complaint/unsubscribe handling for Sentinel's own outbound
mail (Phishing Simulation roadmap Phase 17) — this is what makes ramping
real sending volume responsible instead of reckless: without it, a bad
address just gets retried forever with no visibility.

Signature verification follows the same "trust nothing without
verification" discipline this codebase already applies to unauthenticated
inbound traffic elsewhere (phishing_track.py's tracking routes never trust
an unrecognized token; this never trusts an unsigned/mis-signed payload).
SendGrid's Signed Event Webhook uses ECDSA (P-256, SHA-256) over
`timestamp + raw_body`, verified against a public key SendGrid gives you
when you enable the feature.
"""
from __future__ import annotations

import base64
import logging

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import EmailSuppression

_log = logging.getLogger(__name__)

# Event types that mean "stop sending to this address" — opens (engagement
# signals) and delivered/processed (routine success) never suppress.
_SUPPRESSING_EVENT_TYPES = {"bounce", "dropped", "spamreport", "unsubscribe"}


def verify_signature(payload: bytes, signature_b64: str, timestamp: str) -> bool:
    """Never raises — an unconfigured public key or a malformed signature
    is just "not verified", the same honest-false the rest of this
    codebase's verification helpers return rather than crashing the
    request. The caller (the webhook router) is responsible for rejecting
    anything this returns False for."""
    if not settings.sendgrid_webhook_public_key or not signature_b64 or not timestamp:
        return False
    try:
        public_key = load_der_public_key(base64.b64decode(settings.sendgrid_webhook_public_key))
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, timestamp.encode() + payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError) as e:
        _log.warning("SendGrid webhook signature verification failed: %s", e)
        return False


async def record_suppression_events(db: AsyncSession, events: list[dict]) -> int:
    """Upserts a real EmailSuppression row for every real
    bounce/dropped/spamreport/unsubscribe event in the batch — idempotent
    on `email` (a second bounce for an already-suppressed address just
    refreshes the reason/detail, never creates a duplicate). Returns the
    number of addresses actually suppressed by this batch."""
    suppressed = 0
    for event in events:
        event_type = event.get("event")
        email = (event.get("email") or "").strip().lower()
        if event_type not in _SUPPRESSING_EVENT_TYPES or not email:
            continue
        detail = event.get("reason") or event.get("response") or None
        stmt = pg_insert(EmailSuppression).values(email=email, reason=event_type, detail=detail)
        stmt = stmt.on_conflict_do_update(
            index_elements=[EmailSuppression.email],
            set_={"reason": stmt.excluded.reason, "detail": stmt.excluded.detail},
        )
        await db.execute(stmt)
        suppressed += 1
    if suppressed:
        await db.commit()
    return suppressed
