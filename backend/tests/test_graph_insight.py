"""
Attack Path Graph "AI Analyst" (Phase 39c) — generate_graph_insight() in
advisor_service.py, reusing that file's own Claude-call pattern. The
Anthropic call is faked the same way test_phishing_content_service.py
fakes it — never hits the real API in this suite. Router-level
fingerprint-gate behavior is tested separately below.
"""
from app.config import settings
from app.services import advisor_service as svc


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


_CHOKEPOINT = {
    "policy_arn": "arn:aws:iam::123456789012:policy/over-permissioned",
    "policy_name": "over-permissioned-policy",
    "closes_count": 3,
    "total_open_count": 4,
}
_TARGETS = [{"node_id": "account-admin", "open_path_count": 4, "closed_path_count": 0, "worst_severity": "critical"}]


# ── Rule-based fallback (advisor disabled — never touches the network) ──────

async def test_fallback_reports_a_clear_graph_when_zero_open_paths(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", False)
    result = await svc.generate_graph_insight(node_count=2, edge_count=1, open_path_count=0, targets=[], chokepoint=None)
    assert result["is_ai"] is False
    assert result["commend"] is True
    assert "clear" in result["message"].lower()


async def test_fallback_reports_nothing_discovered_yet_when_graph_is_empty(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", False)
    result = await svc.generate_graph_insight(node_count=0, edge_count=0, open_path_count=0, targets=[], chokepoint=None)
    assert "discovered yet" in result["message"].lower()


async def test_fallback_names_the_real_chokepoint_policy_and_counts(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", False)
    result = await svc.generate_graph_insight(
        node_count=5, edge_count=4, open_path_count=4, targets=_TARGETS, chokepoint=_CHOKEPOINT,
    )
    assert result["is_ai"] is False
    assert result["commend"] is False
    assert "over-permissioned-policy" in result["message"]
    assert "3" in result["message"] and "4" in result["message"]


async def test_fallback_when_paths_exist_but_no_chokepoint(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", False)
    result = await svc.generate_graph_insight(node_count=3, edge_count=2, open_path_count=2, targets=[], chokepoint=None)
    assert "2" in result["message"]
    assert result["commend"] is False


# ── Real LLM path, Anthropic client faked ────────────────────────────────────

async def test_llm_path_returns_the_parsed_message_and_is_ai_true(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", True)
    monkeypatch.setattr(settings, "advisor_provider", "claude")
    monkeypatch.setattr(settings, "anthropic_api_key", "fake-key")
    fake_json = '{"message": "Patch the shared policy to close 3 of 4 paths.", "citations": []}'
    monkeypatch.setattr(svc._anthropic, "AsyncAnthropic", lambda **kwargs: _FakeAnthropicClient(response_text=fake_json))

    result = await svc.generate_graph_insight(
        node_count=5, edge_count=4, open_path_count=4, targets=_TARGETS, chokepoint=_CHOKEPOINT,
    )
    assert result["is_ai"] is True
    assert result["message"] == "Patch the shared policy to close 3 of 4 paths."
    assert result["model"] == settings.advisor_claude_model


async def test_llm_failure_falls_back_to_the_rule_based_message(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", True)
    monkeypatch.setattr(settings, "advisor_provider", "claude")
    monkeypatch.setattr(settings, "anthropic_api_key", "fake-key")
    monkeypatch.setattr(svc._anthropic, "AsyncAnthropic", lambda **kwargs: _FakeAnthropicClient(raises=RuntimeError("boom")))

    result = await svc.generate_graph_insight(
        node_count=5, edge_count=4, open_path_count=4, targets=_TARGETS, chokepoint=_CHOKEPOINT,
    )
    assert result["is_ai"] is False
    assert "over-permissioned-policy" in result["message"]  # same real rule-based content, not an error string


async def test_llm_unparseable_response_falls_back_gracefully(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", True)
    monkeypatch.setattr(settings, "advisor_provider", "claude")
    monkeypatch.setattr(settings, "anthropic_api_key", "fake-key")
    monkeypatch.setattr(svc._anthropic, "AsyncAnthropic", lambda **kwargs: _FakeAnthropicClient(response_text="not json"))

    result = await svc.generate_graph_insight(node_count=2, edge_count=1, open_path_count=0, targets=[], chokepoint=None)
    assert result["is_ai"] is False
    assert "clear" in result["message"].lower()


# ── Simulate-the-Fix's "verified closed" narrative (generate_fix_verification_summary) ──
# The WHETHER-closed fact comes from real CloudPrivEscPath.status/closed_at data
# (graph_service._compute_fix_verifications) — this function only narrates it and
# must never be able to make something read as "closed" that the data doesn't support.

_FULLY_CLOSED = [{
    "policy_arn": "arn:aws:iam::123456789012:policy/leaky", "policy_name": "leaky",
    "closed_count": 2, "still_open_count": 0, "fully_closed": True,
    "latest_closed_at": "2026-09-24T00:00:00+00:00",
    "closed_paths": [],
}]
_PARTIALLY_CLOSED = [{
    "policy_arn": "arn:aws:iam::123456789012:policy/leaky", "policy_name": "leaky",
    "closed_count": 1, "still_open_count": 1, "fully_closed": False,
    "latest_closed_at": "2026-09-24T00:00:00+00:00",
    "closed_paths": [],
}]


async def test_fallback_reports_nothing_verified_yet_when_list_is_empty(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", False)
    result = await svc.generate_fix_verification_summary([])
    assert result["is_ai"] is False
    assert "no fixes" in result["message"].lower() or "not been verified" in result["message"].lower() or "no fixes have been verified" in result["message"].lower()


async def test_fallback_states_fully_closed_plainly(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", False)
    result = await svc.generate_fix_verification_summary(_FULLY_CLOSED)
    assert result["is_ai"] is False
    assert "leaky" in result["message"]
    assert "2" in result["message"]
    assert "fully closed" in result["message"].lower()


async def test_fallback_discloses_partial_closure_not_falsely_green(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", False)
    result = await svc.generate_fix_verification_summary(_PARTIALLY_CLOSED)
    assert "still has an open path" in result["message"].lower() or "not fully remediated" in result["message"].lower()


async def test_fix_verification_llm_path_returns_parsed_message(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", True)
    monkeypatch.setattr(settings, "advisor_provider", "claude")
    monkeypatch.setattr(settings, "anthropic_api_key", "fake-key")
    fake_json = '{"message": "Re-scan confirmed both paths through leaky are closed.", "citations": []}'
    monkeypatch.setattr(svc._anthropic, "AsyncAnthropic", lambda **kwargs: _FakeAnthropicClient(response_text=fake_json))

    result = await svc.generate_fix_verification_summary(_FULLY_CLOSED)
    assert result["is_ai"] is True
    assert result["message"] == "Re-scan confirmed both paths through leaky are closed."


async def test_fix_verification_llm_failure_falls_back_to_rule_based(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", True)
    monkeypatch.setattr(settings, "advisor_provider", "claude")
    monkeypatch.setattr(settings, "anthropic_api_key", "fake-key")
    monkeypatch.setattr(svc._anthropic, "AsyncAnthropic", lambda **kwargs: _FakeAnthropicClient(raises=RuntimeError("boom")))

    result = await svc.generate_fix_verification_summary(_FULLY_CLOSED)
    assert result["is_ai"] is False
    assert "leaky" in result["message"]
