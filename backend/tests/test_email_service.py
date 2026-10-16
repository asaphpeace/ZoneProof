"""
Real transport tests for email_service.py's SendGrid migration (Phishing
Simulation roadmap Phase 17). httpx.AsyncClient is faked the same way
test_dropbox_sign_service.py fakes outbound HTTP calls — no real SendGrid
account needed to prove the payload/auth/error-handling logic is correct.
"""
import uuid

import httpx

from app.config import settings
from app.models import EmailSuppression
from app.services import email_service as svc


class _FakeResponse:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    def __init__(self, response: _FakeResponse):
        self._response = response
        self.posted: dict = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, json=None, headers=None):
        self.posted["url"] = url
        self.posted["json"] = json
        self.posted["headers"] = headers
        return self._response


async def test_send_email_logs_to_stdout_in_dev_mode_when_no_api_key(db_session, monkeypatch, caplog):
    monkeypatch.setattr(settings, "sendgrid_api_key", "")
    calls = []
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: calls.append(1) or _FakeClient(_FakeResponse(202)))

    result = await svc.send_email(db_session, "jane@example.com", "Test subject", "<p>body</p>")
    assert result is True
    assert calls == []  # never actually called out — dev mode logs instead


async def test_send_email_calls_sendgrid_with_real_payload_and_returns_true_on_success(db_session, monkeypatch):
    monkeypatch.setattr(settings, "sendgrid_api_key", "fake-key")
    fake_client = _FakeClient(_FakeResponse(202))
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: fake_client)

    result = await svc.send_email(db_session, "jane@example.com", "Test subject", "<p>body</p>")
    assert result is True
    assert fake_client.posted["url"] == svc._SENDGRID_MAIL_SEND_URL
    assert fake_client.posted["headers"]["Authorization"] == "Bearer fake-key"
    payload = fake_client.posted["json"]
    assert payload["personalizations"] == [{"to": [{"email": "jane@example.com"}]}]
    assert payload["subject"] == "Test subject"
    assert {"type": "text/html", "value": "<p>body</p>"} in payload["content"]


async def test_send_email_returns_false_on_a_real_sendgrid_error_status(db_session, monkeypatch):
    monkeypatch.setattr(settings, "sendgrid_api_key", "fake-key")
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _FakeClient(_FakeResponse(400, "bad request")))

    result = await svc.send_email(db_session, "jane@example.com", "Test subject", "<p>body</p>")
    assert result is False


async def test_send_email_skips_a_suppressed_address_without_calling_sendgrid(db_session, monkeypatch):
    monkeypatch.setattr(settings, "sendgrid_api_key", "fake-key")
    db_session.add(EmailSuppression(id=uuid.uuid4(), email="bounced@example.com", reason="bounce", detail="mailbox full"))
    await db_session.commit()

    calls = []
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: calls.append(1) or _FakeClient(_FakeResponse(202)))

    result = await svc.send_email(db_session, "bounced@example.com", "Test subject", "<p>body</p>")
    assert result is False
    assert calls == []  # suppressed before ever reaching the network


async def test_send_email_suppression_check_is_case_and_whitespace_insensitive(db_session, monkeypatch):
    monkeypatch.setattr(settings, "sendgrid_api_key", "fake-key")
    db_session.add(EmailSuppression(id=uuid.uuid4(), email="bounced@example.com", reason="bounce"))
    await db_session.commit()

    result = await svc.send_email(db_session, "  Bounced@Example.com  ", "Test subject", "<p>body</p>")
    assert result is False
