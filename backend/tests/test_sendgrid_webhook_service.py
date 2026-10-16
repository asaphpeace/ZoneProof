"""
Real ECDSA signature verification and suppression-list recording for
SendGrid's Event Webhook (Phishing Simulation roadmap Phase 17). Uses a
real, deterministic EC P-256 keypair generated once for these tests — the
private key signs a payload exactly the way SendGrid's real signing
mechanism would, so verify_signature() is proven against real
cryptography, not a mocked verifier.
"""
import base64
import json
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.config import settings
from app.models import EmailSuppression
from app.services import sendgrid_webhook_service as svc

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


def _sign(payload: bytes, timestamp: str) -> str:
    signature = _PRIVATE_KEY.sign(timestamp.encode() + payload, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode()


def test_verify_signature_accepts_a_real_correctly_signed_payload(monkeypatch):
    monkeypatch.setattr(settings, "sendgrid_webhook_public_key", _PUBLIC_KEY_B64)
    payload = json.dumps([{"event": "bounce", "email": "a@example.com"}]).encode()
    timestamp = "1700000000"
    assert svc.verify_signature(payload, _sign(payload, timestamp), timestamp) is True


def test_verify_signature_rejects_a_tampered_payload(monkeypatch):
    monkeypatch.setattr(settings, "sendgrid_webhook_public_key", _PUBLIC_KEY_B64)
    payload = json.dumps([{"event": "bounce", "email": "a@example.com"}]).encode()
    timestamp = "1700000000"
    real_signature = _sign(payload, timestamp)
    tampered_payload = json.dumps([{"event": "bounce", "email": "attacker@example.com"}]).encode()
    assert svc.verify_signature(tampered_payload, real_signature, timestamp) is False


def test_verify_signature_rejects_when_no_public_key_configured(monkeypatch):
    monkeypatch.setattr(settings, "sendgrid_webhook_public_key", "")
    payload = b"[]"
    assert svc.verify_signature(payload, _sign(payload, "1700000000"), "1700000000") is False


def test_verify_signature_rejects_a_garbage_signature(monkeypatch):
    monkeypatch.setattr(settings, "sendgrid_webhook_public_key", _PUBLIC_KEY_B64)
    assert svc.verify_signature(b"[]", "not-a-real-signature", "1700000000") is False


async def test_record_suppression_events_creates_rows_for_real_suppressing_event_types(db_session):
    events = [
        {"event": "bounce", "email": "bounced@example.com", "reason": "550 mailbox full"},
        {"event": "spamreport", "email": "complained@example.com"},
        {"event": "delivered", "email": "fine@example.com"},  # not a suppressing type
        {"event": "open", "email": "fine@example.com"},  # not a suppressing type
    ]
    count = await svc.record_suppression_events(db_session, events)
    assert count == 2

    from sqlalchemy import select
    rows = (await db_session.execute(select(EmailSuppression))).scalars().all()
    emails = {r.email: r.reason for r in rows}
    assert emails == {"bounced@example.com": "bounce", "complained@example.com": "spamreport"}


async def test_record_suppression_events_ignores_events_with_no_suppressing_type(db_session):
    count = await svc.record_suppression_events(db_session, [{"event": "delivered", "email": "fine@example.com"}])
    assert count == 0

    from sqlalchemy import select
    rows = (await db_session.execute(select(EmailSuppression))).scalars().all()
    assert rows == []


async def test_record_suppression_events_upserts_without_duplicating_an_existing_suppression(db_session):
    db_session.add(EmailSuppression(id=uuid.uuid4(), email="bounced@example.com", reason="bounce", detail="first bounce"))
    await db_session.commit()

    await svc.record_suppression_events(db_session, [{"event": "bounce", "email": "bounced@example.com", "reason": "second bounce, different reason"}])

    from sqlalchemy import select
    rows = (await db_session.execute(select(EmailSuppression).where(EmailSuppression.email == "bounced@example.com"))).scalars().all()
    assert len(rows) == 1  # still exactly one row, not a duplicate
    assert rows[0].detail == "second bounce, different reason"  # refreshed, not stale
