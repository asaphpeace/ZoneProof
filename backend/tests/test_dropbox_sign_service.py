"""
Dropbox Sign integration for the Engagement rules-of-engagement gate.
render_roe_pdf is monkeypatched out in create_signature_request tests (same
reasoning as pdf_report_service having no dedicated test file yet — real
Playwright/Chromium rendering isn't what's under test here); httpx.AsyncClient
is faked the same way test_exposure_scan_service.py fakes outbound HTTP calls.
"""
import uuid

import httpx
import pytest

from app.config import settings
from app.models import Engagement, Tenant
from app.services import dropbox_sign_service as svc


def _engagement(tier="cloud", scope=None) -> Engagement:
    return Engagement(
        id=uuid.uuid4(), tenant_id=uuid.uuid4(), tier=tier, scope=scope or {}, status="draft",
    )


def _tenant() -> Tenant:
    return Tenant(id=uuid.uuid4(), name="Acme Corp")


def test_build_roe_html_includes_text_tags_and_signer_identity():
    html = svc.build_roe_html(_engagement(scope={"cloud_account_connection_ids": ["abc-123"]}), _tenant(), "Jane Doe", "jane@example.com")
    assert "[sig|req|signer1]" in html
    assert "[date|req|signer1]" in html
    assert "Jane Doe" in html
    assert "jane@example.com" in html
    assert "Acme Corp" in html
    assert "abc-123" in html


def test_build_roe_html_states_the_cadence_for_a_phishing_engagement():
    html = svc.build_roe_html(
        _engagement(tier="phishing", scope={"cadence_days": 90, "target_list_id": "tl-1", "template_id": "shared-document"}),
        _tenant(), "Jane Doe", "jane@example.com",
    )
    assert "every 90 days" in html
    assert "not a single campaign" in html


def test_build_roe_html_omits_cadence_line_for_non_phishing_tiers():
    html = svc.build_roe_html(_engagement(tier="cloud", scope={}), _tenant(), "Jane Doe", "jane@example.com")
    assert "every" not in html or "days, on an ongoing basis" not in html


def test_build_roe_html_omits_cadence_line_when_phishing_scope_has_no_cadence():
    html = svc.build_roe_html(_engagement(tier="phishing", scope={}), _tenant(), "Jane Doe", "jane@example.com")
    assert "on an ongoing basis" not in html


def test_build_roe_html_handles_empty_scope():
    html = svc.build_roe_html(_engagement(scope={}), _tenant(), "Jane Doe", "jane@example.com")
    assert "No additional scope restrictions" in html


async def test_create_signature_request_raises_without_api_key(monkeypatch):
    monkeypatch.setattr(settings, "dropbox_sign_api_key", "")
    with pytest.raises(svc.DropboxSignError):
        await svc.create_signature_request(_engagement(), _tenant(), "Jane Doe", "jane@example.com")


async def test_create_signature_request_returns_id_and_details_url(monkeypatch):
    monkeypatch.setattr(settings, "dropbox_sign_api_key", "fake-key")

    async def fake_render(engagement, tenant, signer_name, signer_email):
        return b"%PDF-fake"

    monkeypatch.setattr(svc, "render_roe_pdf", fake_render)

    posted = {}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"signature_request": {"signature_request_id": "sr-123", "details_url": "https://app.hellosign.com/sr-123"}}

    class _FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, data=None, files=None, auth=None):
            posted["url"] = url
            posted["data"] = data
            posted["auth"] = auth
            return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _FakeClient())

    sig_id, details_url = await svc.create_signature_request(_engagement(), _tenant(), "Jane Doe", "jane@example.com")
    assert sig_id == "sr-123"
    assert details_url == "https://app.hellosign.com/sr-123"
    assert posted["data"]["signers[0][email_address]"] == "jane@example.com"
    assert posted["auth"] == ("fake-key", "")


async def test_create_signature_request_raises_on_http_error(monkeypatch):
    monkeypatch.setattr(settings, "dropbox_sign_api_key", "fake-key")

    async def fake_render(engagement, tenant, signer_name, signer_email):
        return b"%PDF-fake"

    monkeypatch.setattr(svc, "render_roe_pdf", fake_render)

    class _FakeResponse:
        status_code = 401
        text = "Unauthorized"

    class _FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, data=None, files=None, auth=None):
            return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _FakeClient())

    with pytest.raises(svc.DropboxSignError):
        await svc.create_signature_request(_engagement(), _tenant(), "Jane Doe", "jane@example.com")


def test_verify_webhook_event_accepts_a_correctly_signed_event(monkeypatch):
    import hmac
    import json
    from hashlib import sha256

    monkeypatch.setattr(settings, "dropbox_sign_api_key", "fake-key")
    event_time, event_type = "1700000000", "signature_request_all_signed"
    event_hash = hmac.new(b"fake-key", f"{event_time}{event_type}".encode(), sha256).hexdigest()
    raw = json.dumps({"event": {"event_time": event_time, "event_type": event_type, "event_hash": event_hash}})

    payload = svc.verify_webhook_event(raw)
    assert payload["event"]["event_type"] == "signature_request_all_signed"


def test_verify_webhook_event_rejects_a_tampered_hash(monkeypatch):
    import json

    monkeypatch.setattr(settings, "dropbox_sign_api_key", "fake-key")
    raw = json.dumps({"event": {"event_time": "1700000000", "event_type": "signature_request_all_signed", "event_hash": "not-the-real-hash"}})

    with pytest.raises(ValueError):
        svc.verify_webhook_event(raw)


def test_verify_webhook_event_requires_configured_api_key(monkeypatch):
    import json

    monkeypatch.setattr(settings, "dropbox_sign_api_key", "")
    raw = json.dumps({"event": {"event_time": "1700000000", "event_type": "x", "event_hash": "whatever"}})

    with pytest.raises(ValueError):
        svc.verify_webhook_event(raw)
