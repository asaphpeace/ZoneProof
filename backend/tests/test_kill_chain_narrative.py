"""
Kill Chain Narrative — tests the rule-based core of generate_kill_chain_
narrative with settings.advisor_enabled monkeypatched to False, the same
strategy available for generate_graph_insight itself (no existing test file
covers that function — only tests/test_advisor_fingerprint.py, which tests
the generic compute_fingerprint/is_unchanged/remember_fingerprint caching
helpers this feature also reuses, not insight generation). Deterministically
exercises the rule-based message and the real, independently-verifiable
citations without needing to mock an LLM call.
"""
from app.config import settings
from app.services.advisor_service import generate_kill_chain_narrative

_ADMIN_CHAIN = {
    "target_id": "account-admin",
    "target_label": "account-admin",
    "outcome": "Full AWS account administrative control",
    "chain_severity": "critical",
    "hops": [
        {
            "edge_type": "exposed_to_internet", "source": "internet", "target": "arn:aws:ec2:...:instance/i-x",
            "source_label": "Public Internet", "target_label": "EC2 instance i-x",
            "severity": "critical", "remediation": "Restrict ingress...",
        },
        {
            "edge_type": "runs_as", "source": "arn:aws:ec2:...:instance/i-x", "target": "arn:aws:iam::...:role/demo",
            "source_label": "EC2 instance i-x", "target_label": "IAM role demo",
            "severity": "high", "remediation": "Least privilege...",
        },
        {
            "edge_type": "priv_esc", "source": "arn:aws:iam::...:role/demo", "target": "account-admin",
            "source_label": "IAM role demo", "target_label": "account-admin",
            "severity": "critical", "remediation": "Remove iam:PassRole...",
        },
    ],
}

_DATA_CHAIN = {
    "target_id": "arn:aws:s3:::customer-data",
    "target_label": "S3 bucket customer-data",
    "outcome": "Access to S3 bucket customer-data, tagged 'customer-pii'",
    "chain_severity": "high",
    "hops": [
        {
            "edge_type": "runs_as", "source": "arn:aws:ec2:...:instance/i-x", "target": "arn:aws:iam::...:role/demo",
            "source_label": "EC2 instance i-x", "target_label": "IAM role demo",
            "severity": "high", "remediation": "Least privilege...",
        },
        {
            "edge_type": "can_access", "source": "arn:aws:iam::...:role/demo", "target": "arn:aws:s3:::customer-data",
            "source_label": "IAM role demo", "target_label": "S3 bucket customer-data",
            "severity": "high", "remediation": "Scope this principal's S3 statements...",
        },
    ],
}


async def test_generate_kill_chain_narrative_empty_when_no_chains(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", False)
    result = await generate_kill_chain_narrative([])
    assert result["is_ai"] is False
    assert result["citations"] == []
    assert "no real, connected kill chain" in result["message"].lower()


async def test_generate_kill_chain_narrative_rule_based_core_single_chain(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", False)
    result = await generate_kill_chain_narrative([_ADMIN_CHAIN])
    assert result["is_ai"] is False
    assert "3 real hops" in result["message"]
    assert "Full AWS account administrative control" in result["message"]


async def test_generate_kill_chain_narrative_rule_based_core_multiple_chains(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", False)
    result = await generate_kill_chain_narrative([_ADMIN_CHAIN, _DATA_CHAIN])
    assert "and separately" in result["message"]
    assert "Full AWS account administrative control" in result["message"]
    assert "customer-pii" in result["message"]


async def test_generate_kill_chain_narrative_citations_are_deterministic_from_real_hops(monkeypatch):
    # The explicit fix over generate_graph_insight's own known gap — these
    # must come from the real input hops, never from any generated text.
    monkeypatch.setattr(settings, "advisor_enabled", False)
    result = await generate_kill_chain_narrative([_ADMIN_CHAIN])
    assert result["citations"] == [
        "exposed_to_internet: Public Internet → EC2 instance i-x (critical)",
        "runs_as: EC2 instance i-x → IAM role demo (high)",
        "priv_esc: IAM role demo → account-admin (critical)",
    ]


async def test_generate_kill_chain_narrative_citations_span_multiple_chains(monkeypatch):
    monkeypatch.setattr(settings, "advisor_enabled", False)
    result = await generate_kill_chain_narrative([_ADMIN_CHAIN, _DATA_CHAIN])
    assert len(result["citations"]) == len(_ADMIN_CHAIN["hops"]) + len(_DATA_CHAIN["hops"])
