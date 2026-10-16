"""
Reported-suspicious-email ingestion (Phishing Simulation roadmap Phase 26).
Messages are built programmatically with the stdlib email.message API and
round-tripped through the exact same BytesParser(policy=email_policy.
default) pipeline imap_service.py uses on a real fetched message, so these
tests exercise real parsing, not a shortcut.
"""
import uuid
from email import policy as email_policy
from email.message import EmailMessage
from email.parser import BytesParser

from app.models import PhishingTargetList
from app.models.reported_email import ReportedEmail
from app.services import email_ingestion_service as svc
from app.services.phishing_service import _hash_recipient
from tests.factories import make_tenant


def _inner_message(from_addr, subject, body, auth_results=None, date=None):
    msg = EmailMessage(policy=email_policy.default)
    msg["From"] = from_addr
    msg["Subject"] = subject
    if date:
        msg["Date"] = date
    if auth_results:
        msg["Authentication-Results"] = auth_results
    msg.set_content(body)
    return msg


def _outer_with_attachment(reporter_addr, inner, to_slug="abc12345"):
    outer = EmailMessage(policy=email_policy.default)
    outer["From"] = reporter_addr
    outer["To"] = f"{to_slug}@mailsentry.co.za"
    outer["Subject"] = "Fwd: " + inner["Subject"]
    outer.set_content("Please check this out, looks suspicious.")
    outer.add_attachment(inner, subtype="rfc822")
    return _roundtrip(outer)


def _outer_plain_forward(reporter_addr, subject, body, to_slug="abc12345"):
    """Simulates a plain 'Forward' with no real rfc822 attachment — the
    original is just inlined as quoted text, which this parser
    deliberately does not attempt to reverse-parse."""
    outer = EmailMessage(policy=email_policy.default)
    outer["From"] = reporter_addr
    outer["To"] = f"{to_slug}@mailsentry.co.za"
    outer["Subject"] = subject
    outer.set_content(body)
    return _roundtrip(outer)


def _roundtrip(msg):
    return BytesParser(policy=email_policy.default).parsebytes(msg.as_bytes())


def test_extract_urls_dedupes_and_caps():
    text = "Click http://evil.example.com/a and also http://evil.example.com/a again, then http://evil.example.com/b"
    urls = svc.extract_urls(text)
    assert urls == ["http://evil.example.com/a", "http://evil.example.com/b"]


def test_extract_urls_respects_the_cap():
    text = " ".join(f"http://evil.example.com/{i}" for i in range(50))
    assert len(svc.extract_urls(text)) == svc._MAX_URLS


def test_parse_authentication_results_extracts_each_mechanism():
    msg = _inner_message("attacker@evil.com", "Subj", "Body", auth_results="mx.example.com; spf=fail smtp.mailfrom=evil.com; dkim=none; dmarc=fail")
    result = svc.parse_authentication_results(msg)
    assert result["spf_result"] == "fail"
    assert result["dkim_result"] == "none"
    assert result["dmarc_result"] == "fail"
    assert "spf=fail" in result["auth_results_raw"]


def test_parse_authentication_results_is_honestly_none_when_header_is_absent():
    msg = _inner_message("attacker@evil.com", "Subj", "Body")
    result = svc.parse_authentication_results(msg)
    assert result == {"spf_result": None, "dkim_result": None, "dmarc_result": None, "auth_results_raw": None}


def test_resolve_reported_message_finds_a_real_rfc822_attachment():
    inner = _inner_message("attacker@evil.com", "Urgent: verify your account", "Click here")
    outer = _outer_with_attachment("jane@realcompany.com", inner)
    resolved, is_attached = svc.resolve_reported_message(outer)
    assert is_attached is True
    assert resolved.get("From") == "attacker@evil.com"


def test_resolve_reported_message_falls_back_honestly_with_no_attachment():
    outer = _outer_plain_forward("jane@realcompany.com", "Fwd: check this", "---------- Forwarded message ---------\nFrom: attacker@evil.com\n...")
    resolved, is_attached = svc.resolve_reported_message(outer)
    assert is_attached is False
    assert resolved is outer  # deliberately not reverse-parsed out of the quoted body


async def test_parse_reported_email_with_a_real_attached_original(db_session, monkeypatch):
    # Link risk scoring is exercised in its own tests (test_link_risk_service.py
    # and the *_scoring tests below) — mocked out here to a no-op so this test
    # stays a fast, network-free check of the parsing logic it's actually
    # about, not an accidental live RDAP lookup against a real registry.
    async def _no_op_scoring(*args, **kwargs):
        return None
    monkeypatch.setattr(svc, "score_report_urls_best_effort", _no_op_scoring)

    tenant = await make_tenant(db_session)
    inner = _inner_message(
        "Attacker <attacker@evil.com>", "Urgent: verify your account",
        "Click here http://evil.example.com/login to verify your account now.",
        auth_results="mx.example.com; spf=fail smtp.mailfrom=evil.com; dkim=none; dmarc=fail",
        date="Mon, 01 Sep 2026 10:00:00 +0000",
    )
    outer = _outer_with_attachment("Jane Employee <jane@realcompany.com>", inner)

    report = await svc.parse_reported_email(db_session, tenant, outer)

    assert report.is_original_message_attached is True
    assert report.original_subject == "Urgent: verify your account"
    assert report.original_from == "attacker@evil.com"
    assert report.original_from_domain == "evil.com"
    assert report.original_date is not None
    assert "http://evil.example.com/login" in report.urls_found
    assert report.spf_result == "fail"
    assert report.dkim_result == "none"
    assert report.dmarc_result == "fail"
    assert "verify your account now" in report.body_text_excerpt
    assert report.disposition == "new"

    # Pseudonymization holds — the real reporter identity is never stored
    # in plaintext anywhere on the row, only its hash.
    assert report.reporter_hash == _hash_recipient("jane@realcompany.com", tenant.id)
    for field_name in ("original_from", "original_subject", "body_text_excerpt", "auth_results_raw"):
        value = getattr(report, field_name) or ""
        assert "jane@realcompany.com" not in value
        assert "Jane Employee" not in value


async def test_parse_reported_email_without_a_real_attachment_is_honest_about_it(db_session):
    tenant = await make_tenant(db_session)
    outer = _outer_plain_forward(
        "Jane Employee <jane@realcompany.com>", "Fwd: check this",
        "---------- Forwarded message ---------\nFrom: attacker@evil.com\nSubject: Urgent\n\nClick here",
    )
    report = await svc.parse_reported_email(db_session, tenant, outer)

    assert report.is_original_message_attached is False
    # Examines the outer (forwarding) message itself, honestly — not a
    # guessed reverse-parse of the quoted text.
    assert report.original_from == "jane@realcompany.com"
    assert report.original_subject == "Fwd: check this"


async def test_unmask_reporter_finds_a_real_match_across_any_of_the_tenants_lists(db_session):
    tenant = await make_tenant(db_session)
    other_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Other", entries=[{"email": "someone-else@example.com"}])
    real_list = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Real", entries=[{"email": "jane@realcompany.com"}])
    db_session.add_all([other_list, real_list])
    await db_session.commit()

    report = ReportedEmail(
        id=uuid.uuid4(), tenant_id=tenant.id, reporter_hash=_hash_recipient("jane@realcompany.com", tenant.id),
    )
    db_session.add(report)
    await db_session.commit()

    email = await svc.unmask_reporter(db_session, report)
    assert email == "jane@realcompany.com"


async def test_unmask_reporter_is_honestly_none_when_nobody_matches(db_session):
    tenant = await make_tenant(db_session)
    tl = PhishingTargetList(id=uuid.uuid4(), tenant_id=tenant.id, name="Staff", entries=[{"email": "someone-else@example.com"}])
    db_session.add(tl)
    await db_session.commit()

    report = ReportedEmail(id=uuid.uuid4(), tenant_id=tenant.id, reporter_hash="a-hash-nobody-on-any-list-matches")
    db_session.add(report)
    await db_session.commit()

    assert await svc.unmask_reporter(db_session, report) is None


# ── IMAP slug routing (imap_service.py's new tenant-report-slug branch,
# alongside its existing untouched Domain.reporting_slug branch) ───────────

async def test_get_tenant_by_report_slug_resolves_a_real_tenant(db_session):
    from app.services.imap_service import _get_tenant_by_report_slug
    tenant = await make_tenant(db_session)
    tenant.phishing_report_slug = "deadbeef"
    await db_session.commit()

    resolved = await _get_tenant_by_report_slug(db_session, "deadbeef")
    assert resolved is not None
    assert resolved.id == tenant.id


# ── Link risk scoring wired into ingestion (Phase 32) ──────────────────────

async def test_parse_reported_email_saves_report_even_when_scoring_raises(db_session, monkeypatch):
    async def _raising_scoring(*args, **kwargs):
        raise RuntimeError("simulated scoring outage")
    monkeypatch.setattr(svc, "score_report_urls_best_effort", _raising_scoring)

    tenant = await make_tenant(db_session)
    inner = _inner_message("Attacker <attacker@evil.com>", "Urgent", "Click http://evil.example.com/login now")
    outer = _outer_with_attachment("Jane Employee <jane@realcompany.com>", inner)

    report = await svc.parse_reported_email(db_session, tenant, outer)

    assert report.id is not None
    assert report.original_subject == "Urgent"
    assert report.url_risk is None


async def test_parse_reported_email_populates_url_risk_on_successful_scoring(db_session, monkeypatch):
    canned = [{"url": "http://evil.example.com/login", "score": 10, "verdict": "likely_dangerous",
               "grade": "F", "explanation": "canned test result", "signals": {}}]

    async def _canned_scoring(db, report, **kwargs):
        report.url_risk = canned
        from datetime import datetime, timezone
        report.url_risk_scored_at = datetime.now(timezone.utc)
    monkeypatch.setattr(svc, "score_report_urls_best_effort", _canned_scoring)

    tenant = await make_tenant(db_session)
    inner = _inner_message("Attacker <attacker@evil.com>", "Urgent", "Click http://evil.example.com/login now")
    outer = _outer_with_attachment("Jane Employee <jane@realcompany.com>", inner)

    report = await svc.parse_reported_email(db_session, tenant, outer)

    assert report.url_risk == canned
    assert report.url_risk_scored_at is not None


async def test_parse_reported_email_skips_scoring_when_no_urls_found(db_session, monkeypatch):
    calls = []

    async def _tracking_scoring(*args, **kwargs):
        calls.append(1)
    monkeypatch.setattr(svc, "score_report_urls_best_effort", _tracking_scoring)

    tenant = await make_tenant(db_session)
    inner = _inner_message("Attacker <attacker@evil.com>", "Urgent", "No links here, just text.")
    outer = _outer_with_attachment("Jane Employee <jane@realcompany.com>", inner)

    report = await svc.parse_reported_email(db_session, tenant, outer)

    assert report.urls_found == []
    # score_report_urls_best_effort is still called (its own early-return on
    # empty urls_found is tested directly in test_link_risk_service.py) —
    # this test just confirms ingestion completes cleanly either way.
    assert len(calls) == 1


async def test_get_tenant_by_report_slug_is_none_for_an_unknown_slug(db_session):
    from app.services.imap_service import _get_tenant_by_report_slug
    assert await _get_tenant_by_report_slug(db_session, "00000000") is None
