"""
Unit tests for the pure detection logic in impersonation_scan_service.py —
no real DNS, no real SMTP. Mirrors test_exposure_scan_service.py's approach:
monkeypatch the lower-level helpers (dns.resolver, the sync SMTP function)
so these tests assert on the matching/orchestration logic itself.
"""
import smtplib
import uuid
from datetime import datetime, timedelta, timezone

import dns.resolver
from sqlalchemy import select

from app.models import Domain, Engagement, Finding
from app.services import impersonation_scan_service as svc
from tests.factories import make_domain, make_tenant


def test_generate_lookalike_permutations_includes_expected_technique_families():
    candidates = svc._generate_lookalike_permutations("example.com")
    assert "exmple.com" in candidates  # omission
    assert "eexample.com" in candidates  # duplication
    assert "xeample.com" in candidates  # adjacent transposition
    assert "exampl3.com" not in candidates  # sanity: unrelated string absent
    assert "example.net" in candidates  # TLD swap
    assert "example.com" not in candidates  # never includes the real domain


def test_generate_lookalike_permutations_handles_short_labels_gracefully():
    assert svc._generate_lookalike_permutations("a.com") == []
    assert svc._generate_lookalike_permutations("no-dot") == []


async def test_check_lookalike_domains_flags_only_permutations_with_live_records(monkeypatch):
    async def fake_resolve(candidate, record_type):
        if candidate == "exmple.com" and record_type == "MX":
            return ["mx.exmple.com"]
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(svc.resolver, "resolve", fake_resolve)
    monkeypatch.setattr(svc, "_generate_lookalike_permutations", lambda d: ["exmple.com", "exarnple.com"])

    hits = await svc.check_lookalike_domains("example.com")
    assert len(hits) == 1
    assert hits[0] == {"domain": "exmple.com", "record_type": "MX"}


def test_send_spoof_test_sync_reports_delivered_when_smtp_accepts(monkeypatch):
    class _FakeSMTP:
        def __init__(self, host, port, timeout=None): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def ehlo(self): pass
        def has_extn(self, name): return False
        def sendmail(self, from_addr, to_addrs, msg): pass

    monkeypatch.setattr(svc.dns.resolver, "resolve", lambda host, rtype: [_FakeMx("mx.target.com", 10)])
    monkeypatch.setattr(svc.smtplib, "SMTP", _FakeSMTP)

    result = svc._send_spoof_test_sync("customer.com", "security@target.com")
    assert result["outcome"] == "delivered"


def test_send_spoof_test_sync_reports_blocked_on_smtp_rejection(monkeypatch):
    class _FakeSMTP:
        def __init__(self, host, port, timeout=None): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def ehlo(self): pass
        def has_extn(self, name): return False
        def sendmail(self, from_addr, to_addrs, msg):
            raise smtplib.SMTPResponseException(550, b"DMARC policy violation")

    monkeypatch.setattr(svc.dns.resolver, "resolve", lambda host, rtype: [_FakeMx("mx.target.com", 10)])
    monkeypatch.setattr(svc.smtplib, "SMTP", _FakeSMTP)

    result = svc._send_spoof_test_sync("customer.com", "security@target.com")
    assert result["outcome"] == "blocked"


def test_send_spoof_test_sync_reports_test_error_when_mx_unresolvable(monkeypatch):
    def fake_resolve(host, rtype):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(svc.dns.resolver, "resolve", fake_resolve)

    result = svc._send_spoof_test_sync("customer.com", "security@nonexistent-target.invalid")
    assert result["outcome"] == "test_error"


class _FakeMx:
    def __init__(self, exchange, preference):
        self.exchange = exchange
        self.preference = preference


async def test_run_impersonation_scan_creates_finding_for_live_lookalike(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant, name="example.com")
    domain.ownership_verified = True
    engagement = Engagement(
        id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, tier="impersonation",
        scope={"test_recipient_email": "security@example.com"}, status="active",
    )
    db_session.add(engagement)
    await db_session.commit()

    async def fake_lookalike(domain_name):
        return [{"domain": "exmple.com", "record_type": "MX"}]

    async def fake_spoof(domain_name, recipient):
        return {"outcome": "blocked", "detail": "rejected"}

    monkeypatch.setattr(svc, "check_lookalike_domains", fake_lookalike)
    monkeypatch.setattr(svc, "send_spoof_test", fake_spoof)

    findings = await svc.run_impersonation_scan(db_session, engagement, domain)
    assert len(findings) == 1
    assert findings[0].check_id == "IMPERSONATION-LOOKALIKE-exmple.com"

    await db_session.refresh(engagement)
    assert engagement.last_scan_status == "success"
    assert engagement.last_scanned_at is not None


async def test_run_impersonation_scan_creates_critical_finding_when_spoof_delivered(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant, name="example.com")
    domain.ownership_verified = True
    engagement = Engagement(
        id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, tier="impersonation",
        scope={"test_recipient_email": "security@example.com"}, status="active",
    )
    db_session.add(engagement)
    await db_session.commit()

    monkeypatch.setattr(svc, "check_lookalike_domains", lambda d: _empty())
    monkeypatch.setattr(svc, "send_spoof_test", lambda d, r: _delivered())

    findings = await svc.run_impersonation_scan(db_session, engagement, domain)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].check_id == "IMPERSONATION-SPOOF-SEND-TEST"


async def test_run_impersonation_scan_records_failure_without_a_finding_on_test_error(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant, name="example.com")
    domain.ownership_verified = True
    engagement = Engagement(
        id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, tier="impersonation",
        scope={"test_recipient_email": "security@example.com"}, status="active",
    )
    db_session.add(engagement)
    await db_session.commit()

    monkeypatch.setattr(svc, "check_lookalike_domains", lambda d: _empty())
    monkeypatch.setattr(svc, "send_spoof_test", lambda d, r: _test_error())

    findings = await svc.run_impersonation_scan(db_session, engagement, domain)
    assert findings == []

    await db_session.refresh(engagement)
    assert engagement.last_scan_status == "failed"
    assert engagement.last_scan_error


async def test_run_impersonation_scan_skips_unverified_domain(db_session):
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant, name="unverified.com")
    engagement = Engagement(
        id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, tier="impersonation",
        scope={"test_recipient_email": "security@unverified.com"}, status="active",
    )
    db_session.add(engagement)
    await db_session.commit()

    findings = await svc.run_impersonation_scan(db_session, engagement, domain)
    assert findings == []


async def test_poll_all_due_impersonation_domains_skips_recently_scanned(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant, name="example.com")
    domain.ownership_verified = True
    engagement = Engagement(
        id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, tier="impersonation",
        scope={"test_recipient_email": "security@example.com"}, status="active",
        last_scanned_at=datetime.now(timezone.utc) - timedelta(days=2),
    )
    db_session.add(engagement)
    await db_session.commit()

    called = []
    async def fake_run(db, eng, dom):
        called.append(eng.id)
        return []
    monkeypatch.setattr(svc, "run_impersonation_scan", fake_run)

    count = await svc.poll_all_due_impersonation_domains(db_session)
    assert count == 0
    assert called == []


async def test_poll_all_due_impersonation_domains_runs_engagements_past_the_interval(db_session, monkeypatch):
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant, name="example.com")
    domain.ownership_verified = True
    engagement = Engagement(
        id=uuid.uuid4(), tenant_id=tenant.id, domain_id=domain.id, tier="impersonation",
        scope={"test_recipient_email": "security@example.com"}, status="active",
        last_scanned_at=datetime.now(timezone.utc) - timedelta(days=45),
    )
    db_session.add(engagement)
    await db_session.commit()

    called = []
    async def fake_run(db, eng, dom):
        called.append(eng.id)
        return []
    monkeypatch.setattr(svc, "run_impersonation_scan", fake_run)

    count = await svc.poll_all_due_impersonation_domains(db_session)
    assert count == 1
    assert called == [engagement.id]


async def _empty():
    return []


async def _delivered():
    return {"outcome": "delivered", "detail": "accepted"}


async def _test_error():
    return {"outcome": "test_error", "detail": "could not connect"}
