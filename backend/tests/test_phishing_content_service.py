"""
LLM-generated phishing content (Coverage Map plan Phase 7). The Anthropic
call is faked the same way test_oauth_app_risk_service.py fakes outbound
API calls — never hits the real Anthropic API in this suite.
"""
from app.config import settings
from app.services import phishing_content_service as svc


class _FakeContentBlock:
    def __init__(self, text):
        self.text = text


class _FakeResponse:
    def __init__(self, text):
        self.content = [_FakeContentBlock(text)]


class _FakeMessages:
    def __init__(self, response_text=None, raises=None):
        self._response_text = response_text
        self._raises = raises

    async def create(self, **kwargs):
        if self._raises:
            raise self._raises
        return _FakeResponse(self._response_text)


class _FakeAnthropicClient:
    def __init__(self, response_text=None, raises=None):
        self.messages = _FakeMessages(response_text, raises)


async def test_returns_fallback_when_api_key_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "")
    subject, body, was_llm = await svc.generate_campaign_content("password-expiry", "Acme Corp")
    assert was_llm is False
    assert subject  # the static template's subject
    assert "{click_url}" in body


async def test_returns_llm_content_on_success(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "fake-key")
    fake_json = '{"subject": "Your account needs attention", "body_html": "<p>Hello</p><a href=\\"{click_url}\\">Link</a>"}'
    monkeypatch.setattr(
        svc.anthropic, "AsyncAnthropic",
        lambda **kwargs: _FakeAnthropicClient(response_text=fake_json),
    )

    subject, body, was_llm = await svc.generate_campaign_content("password-expiry", "Acme Corp")
    assert was_llm is True
    assert subject == "Your account needs attention"
    assert "{click_url}" in body


async def test_falls_back_when_llm_response_is_not_json(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "fake-key")
    monkeypatch.setattr(
        svc.anthropic, "AsyncAnthropic",
        lambda **kwargs: _FakeAnthropicClient(response_text="not json at all"),
    )

    subject, body, was_llm = await svc.generate_campaign_content("password-expiry", "Acme Corp")
    assert was_llm is False
    assert "{click_url}" in body  # the static fallback template's guarantee


async def test_falls_back_when_llm_drops_the_click_url_placeholder(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "fake-key")
    fake_json = '{"subject": "Subject", "body_html": "<p>No link here at all</p>"}'
    monkeypatch.setattr(
        svc.anthropic, "AsyncAnthropic",
        lambda **kwargs: _FakeAnthropicClient(response_text=fake_json),
    )

    subject, body, was_llm = await svc.generate_campaign_content("password-expiry", "Acme Corp")
    assert was_llm is False
    assert "{click_url}" in body


async def test_falls_back_when_the_api_call_raises(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "fake-key")
    monkeypatch.setattr(
        svc.anthropic, "AsyncAnthropic",
        lambda **kwargs: _FakeAnthropicClient(raises=RuntimeError("API down")),
    )

    subject, body, was_llm = await svc.generate_campaign_content("password-expiry", "Acme Corp")
    assert was_llm is False
    assert "{click_url}" in body


async def test_falls_back_to_first_template_for_an_unknown_lure_category(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "")
    subject, body, was_llm = await svc.generate_campaign_content("not-a-real-category", "Acme Corp")
    assert was_llm is False
    assert subject
    assert "{click_url}" in body
