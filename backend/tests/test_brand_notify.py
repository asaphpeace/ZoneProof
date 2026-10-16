import json
from datetime import datetime, timezone

import pytest

from app.services import brand_notify as bn

ALERT = {"id": "a1", "severity": "critical", "title": "Possible brand impersonation: acme-login.xyz", "body": "It resembles Acme <script>", "action": "Open Brand Guard.", "created_at": "2026-10-06T08:00:00+00:00"}


@pytest.mark.parametrize("kind,target", [
    ("email", "Ann@Example.com"), ("slack", "https://hooks.slack.com/services/T0/B0/xyz"),
    ("teams", "https://acme.webhook.office.com/webhookb2/abc"), ("teams", "https://prod-1.westus.logic.azure.com/workflows/x"), ("webhook", "https://siem.example.com/hook"),
])
def test_good_targets_are_accepted(kind, target):
    assert bn.validate_target(kind, target)


@pytest.mark.parametrize("kind,target", [
    ("email", "not-an-email"), ("email", "a@b.com, c@d.com"), ("email", "a@b.com\nBcc: x@y.com"),
    ("webhook", "http://example.com/hook"),                              # not https
    ("webhook", "https://127.0.0.1/hook"), ("webhook", "https://169.254.169.254/latest/meta-data"), ("webhook", "https://[::1]/x"),   # IP literals
    ("webhook", "https://user:pw@example.com/x"), ("webhook", "https://example.com:8443/x"), ("webhook", "ftp://example.com"), ("webhook", ""),
    ("slack", "https://example.com/services/x"), ("slack", "https://hooks.slack.com.evil.example/x"),
    ("teams", "https://evil.example.com/webhook.office.com"), ("teams", "https://webhook.office.com.evil.example/x"),
    ("bogus", "https://example.com/x"), ("webhook", "https://example.com/" + "a" * 2100),
])
def test_unsafe_or_wrong_targets_are_refused(kind, target):
    with pytest.raises(ValueError):
        bn.validate_target(kind, target)


@pytest.mark.parametrize("ip,ok", [("8.8.8.8", True), ("10.0.0.5", False), ("192.168.1.1", False), ("172.16.0.1", False), ("127.0.0.1", False), ("169.254.169.254", False), ("::1", False), ("fd00::1", False), ("junk", False)])
def test_only_public_addresses_pass(ip, ok):
    assert bn.is_public_address(ip) is ok


async def test_a_host_must_resolve_and_only_to_public_addresses(monkeypatch):
    import asyncio

    class Loop:
        def __init__(self, addrs): self.addrs = addrs
        async def getaddrinfo(self, host, port, type=None):
            if self.addrs is None:
                raise OSError("nxdomain")
            return [(2, 1, 6, "", (a, 443)) for a in self.addrs]
    for addrs, expected in ((["8.8.8.8"], True), (["8.8.8.8", "10.0.0.1"], False), (["127.0.0.1"], False), ([], False), (None, False)):
        monkeypatch.setattr(asyncio, "get_running_loop", lambda a=addrs: Loop(a))
        assert await bn.host_resolves_publicly("x.example.com") is expected


def test_severity_threshold():
    assert bn.passes("warn", "critical") and bn.passes("warn", "warn") and not bn.passes("warn", "info") and bn.passes("critical", "critical") and not bn.passes("critical", "warn")


def test_slack_text_is_escaped_and_links():
    p = bn.slack_payload(ALERT, "https://app.example.com/brand-guard")
    assert "&lt;script&gt;" in p["text"] and "<script>" not in p["text"] and "<https://app.example.com/brand-guard|Open in ZoneProof>" in p["text"]


def test_teams_card_has_the_title_colour_and_action():
    c = bn.teams_payload(ALERT, "https://app.example.com/x")
    assert c["@type"] == "MessageCard" and c["themeColor"] == "FF4D6D" and c["potentialAction"][0]["targets"][0]["uri"] == "https://app.example.com/x"
    assert "potentialAction" not in bn.teams_payload(ALERT, None)


def test_long_text_is_truncated():
    big = {**ALERT, "body": "x" * 5000}
    assert len(bn.slack_payload(big, None)["text"]) < 1200 and len(bn.teams_payload(big, None)["text"]) < 800


def test_webhook_payload_and_signature_round_trip_and_reject_tampering_and_replays():
    body = json.dumps(bn.webhook_payload(ALERT, None)).encode()
    sig = bn.sign(body, "s3cret", "1760000000")
    assert sig.startswith("sha256=") and bn.verify(body, "s3cret", "1760000000", sig)
    assert not bn.verify(body + b" ", "s3cret", "1760000000", sig)           # changed body
    assert not bn.verify(body, "other", "1760000000", sig)                    # wrong secret
    assert not bn.verify(body, "s3cret", "1760000001", sig)                   # different timestamp
    assert not bn.verify(body, "s3cret", "1760000000", "")


def test_email_html_is_escaped_and_text_is_plain():
    subject, html, text = bn.email_parts(ALERT, "https://app.example.com/x?a=1&b=2")
    assert subject.startswith("[ZoneProof] ") and "&lt;script&gt;" in html and "<script>" not in html and "<script>" in text and "&amp;b=2" in html


def test_digest_reads_from_the_summary_numbers():
    d = bn.digest(brand="Acme", summary={"new_24h": 3, "open_candidates": 5, "confirmed": 2, "takedown": 1, "overdue": 1, "went_live_7d": 4}, since=datetime(2026, 10, 6, tzinfo=timezone.utc))
    assert d["title"] == "ZoneProof daily summary for Acme" and "3 new look-alike(s) in the last 24 hours" in d["lines"] and "3 open case(s), 1 overdue" in d["lines"]
    assert bn.digest_alert(d)["severity"] == "info" and "- 5 need a decision" in bn.digest_alert(d)["body"]


def test_cef_escapes_pipes_equals_and_newlines():
    line = bn.to_cef({"kind": "brand_guard.alert", "name": "a|b", "severity": "critical", "at": "2026-10-06T08:00:00Z", "target": "evil=x.com", "detail": "line1\nline2"})
    assert line.startswith("CEF:0|ZoneProof|Brand Guard|1|brand_guard.alert|a\\|b|9|") and "dhost=evil\\=x.com" in line and "\n" not in line


def test_jsonl_is_one_valid_object_per_line():
    out = bn.to_jsonl([{"b": 1, "a": "é"}, {"x": 2}])
    assert [json.loads(l) for l in out.splitlines()] == [{"a": "é", "b": 1}, {"x": 2}] and out.endswith("\n")


def test_a_hostile_title_is_escaped_in_every_channel_because_it_contains_an_attacker_chosen_domain():
    evil = {**ALERT, "title": "Possible brand impersonation: <img src=x onerror=alert(1)>.xyz", "action": "<b>do it</b>"}
    subject, html, text = bn.email_parts(evil, None)
    assert "<img" not in html and "&lt;img" in html and "<b>do it</b>" not in html
    assert "<img" not in bn.slack_payload(evil, None)["text"]
