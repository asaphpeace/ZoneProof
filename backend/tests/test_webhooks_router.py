"""
Router-level tests for the unauthenticated /webhooks/sendgrid/events
receiver (Phishing Simulation roadmap Phase 17) — real signature
verification end to end through the actual HTTP layer, not just the
service function in isolation.
"""
import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.config import settings
from app.models import EmailSuppression

_PRIVATE_KEY = serialization.load_pem_private_key(
    b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgdXKVB3bn7WT7+7E+
6nZzr7y6kxzFJ3bqpm8tZCReFjGhRANCAASpJMJ3tg+bReTCUw9clIv0ww088ibG
TXf/LCF+mFb7r87hP0OUG9O7wMCDo91RGy4mdrM9Iy5ZK5+E5O6T1wg9
-----END PRIVATE KEY-----
""",
    password=None,
)
_PUBLIC_KEY_B64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqSTCd7YPm0XkwlMPXJSL9MMNPPImxk13/ywhfphW+6/O4T9DlBvTu8DAg6PdURsuJnazPSMuWSufhOTuk9cIPQ=="


def _signed_headers(payload: bytes, timestamp: str = "1700000000") -> dict:
    signature = _PRIVATE_KEY.sign(timestamp.encode() + payload, ec.ECDSA(hashes.SHA256()))
    return {
        "X-Twilio-Email-Event-Webhook-Signature": base64.b64encode(signature).decode(),
        "X-Twilio-Email-Event-Webhook-Timestamp": timestamp,
    }


async def test_webhook_rejects_an_unsigned_payload(client, monkeypatch):
    monkeypatch.setattr(settings, "sendgrid_webhook_public_key", _PUBLIC_KEY_B64)
    resp = await client.post("/webhooks/sendgrid/events", json=[{"event": "bounce", "email": "a@example.com"}])
    assert resp.status_code == 401


async def test_webhook_rejects_a_signature_that_does_not_verify(client, monkeypatch):
    monkeypatch.setattr(settings, "sendgrid_webhook_public_key", _PUBLIC_KEY_B64)
    resp = await client.post(
        "/webhooks/sendgrid/events",
        json=[{"event": "bounce", "email": "a@example.com"}],
        headers={"X-Twilio-Email-Event-Webhook-Signature": "not-real", "X-Twilio-Email-Event-Webhook-Timestamp": "1700000000"},
    )
    assert resp.status_code == 401


async def test_webhook_accepts_a_real_signed_payload_and_records_a_real_suppression(client, db_session, monkeypatch):
    monkeypatch.setattr(settings, "sendgrid_webhook_public_key", _PUBLIC_KEY_B64)
    body = [{"event": "bounce", "email": "real-bounce@example.com", "reason": "550 mailbox full"}]
    payload = json.dumps(body).encode()

    resp = await client.post(
        "/webhooks/sendgrid/events",
        content=payload,
        headers={**_signed_headers(payload), "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"received": 1, "suppressed": 1}

    from sqlalchemy import select
    row = await db_session.scalar(select(EmailSuppression).where(EmailSuppression.email == "real-bounce@example.com"))
    assert row is not None
    assert row.reason == "bounce"
