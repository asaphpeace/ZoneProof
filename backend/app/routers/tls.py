from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import Domain, TlsAggregate, TlsPolicy, TlsReport
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.tls import TlsOverviewOut, TlsFailGroupOut, TlsFailTypeOut, TlsMxHostOut, TlsDomainSummaryOut
from app.services.tls_service import generate_record_diff, explain_tls_failure, fetch_mta_sts_policy
from app.services.tls_service import check_mta_sts_dns
from app.schemas.dmarc import RecordDiffOut

router = APIRouter(prefix="/domains/{domain_id}/tls", tags=["tls"])


async def _get_domain(domain_id: str, tenant_id, db: AsyncSession) -> Domain:
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == tenant_id))
    d = result.scalar_one_or_none()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")
    return d


@dataclass
class _WindowAgg:
    """Same fields the overview reads from TlsAggregate, computed for the window."""
    mx_host: str
    reporter_org: str = ""
    total_sessions: int = 0
    successful_sessions: int = 0
    failed_sessions: int = 0
    top_failure_reason: str | None = None
    top_failure_count: int = 0


async def _windowed_aggregates(db: AsyncSession, domain_id, cutoff: datetime) -> list[_WindowAgg]:
    """
    Sessions per MX host from the raw reports whose period ends inside the window.

    The stored TlsAggregate rows are rebuilt from every policy ever received and
    stamped with the start of the current month, so filtering them by days cannot
    window anything: a 7 day view mid-month came back empty. The raw reports
    carry the real reporting period, so the window is applied to those.
    """
    stmt = (
        select(TlsPolicy)
        .join(TlsReport, TlsPolicy.report_id == TlsReport.id)
        .where(TlsPolicy.domain_id == domain_id, TlsReport.period_end >= cutoff)
        .options(selectinload(TlsPolicy.failure_details))
    )
    policies = (await db.execute(stmt)).scalars().all()

    groups: dict[str, _WindowAgg] = {}
    for p in policies:
        mx = p.policy_mx_host or p.policy_domain
        g = groups.setdefault(mx, _WindowAgg(mx_host=mx))
        g.successful_sessions += p.total_successful_session_count
        g.failed_sessions += p.total_failure_session_count
        g.total_sessions += p.total_successful_session_count + p.total_failure_session_count
        for fd in p.failure_details:
            if fd.failed_session_count > g.top_failure_count:
                g.top_failure_count = fd.failed_session_count
                g.top_failure_reason = fd.result_type
    return list(groups.values())


def _severity(failed: int, total: int, reason: str | None) -> str:
    critical_reasons = {"certificate-expired", "starttls-not-supported", "certificate-not-trusted"}
    if reason in critical_reasons and failed > 0:
        return "critical"
    if failed > 0:
        return "warning"
    return "ok"


def _build_fail_types(aggs: list) -> list[TlsFailTypeOut]:
    from collections import Counter
    from sqlalchemy.orm import object_session
    # We sum per top_failure_reason across aggregates
    counts: Counter = Counter()
    for a in aggs:
        if a.top_failure_reason and a.failed_sessions:
            counts[a.top_failure_reason] += a.failed_sessions
    total = sum(counts.values()) or 1
    labels = {
        "certificate-expired":       "Expired certificate",
        "certificate-not-trusted":   "Untrusted certificate",
        "starttls-not-supported":    "STARTTLS not offered",
        "certificate-host-mismatch": "Hostname mismatch",
        "validation-failure":        "Validation failure",
        "tlsa-invalid":              "TLSA / DANE invalid",
        "dnssec-invalid":            "DNSSEC failure",
        "sts-policy-fetch-error":    "MTA-STS fetch error",
        "sts-policy-invalid":        "MTA-STS policy invalid",
        "sts-webpki-invalid":        "WebPKI invalid",
        "no-policy-found":           "No policy found",
    }
    result = []
    for reason, count in counts.most_common():
        result.append(TlsFailTypeOut(
            reason=reason,
            label=labels.get(reason, reason),
            count=count,
            pct=round(count / total * 100, 1),
        ))
    return result


@router.get("", response_model=TlsOverviewOut)
async def get_tls_overview(
    domain_id: str,
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domain = await _get_domain(domain_id, user.tenant_id, db)

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    aggs = await _windowed_aggregates(db, domain.id, cutoff)

    total = sum(a.total_sessions for a in aggs)
    successful = sum(a.successful_sessions for a in aggs)
    failed = sum(a.failed_sessions for a in aggs)
    pass_pct = round(successful / total * 100, 1) if total else 0.0

    fail_groups = []
    for agg in sorted(aggs, key=lambda a: a.failed_sessions, reverse=True):
        if agg.failed_sessions > 0:
            fail_groups.append(TlsFailGroupOut(
                mx_host=agg.mx_host,
                reporter_org=agg.reporter_org,
                failed_sessions=agg.failed_sessions,
                successful_sessions=agg.successful_sessions,
                total_sessions=agg.total_sessions,
                top_failure_reason=agg.top_failure_reason,
                failure_explanation=explain_tls_failure(agg.top_failure_reason or ""),
                severity=_severity(agg.failed_sessions, agg.total_sessions, agg.top_failure_reason),
            ))

    from app.services.advisor_service import _TLS_FIX_ACTIONS, _TLS_FIX_CATEGORY

    mx_hosts = []
    for agg in sorted(aggs, key=lambda a: a.total_sessions, reverse=True):
        has_failure = bool(agg.top_failure_reason and agg.failed_sessions)
        exp = explain_tls_failure(agg.top_failure_reason) if has_failure else None
        mx_hosts.append(TlsMxHostOut(
            mx_host=agg.mx_host,
            total_sessions=agg.total_sessions,
            successful_sessions=agg.successful_sessions,
            failed_sessions=agg.failed_sessions,
            pass_pct=round(agg.successful_sessions / agg.total_sessions * 100, 1) if agg.total_sessions else 0.0,
            top_failure_reason=agg.top_failure_reason if agg.failed_sessions else None,
            failure_explanation=exp,
            severity=_severity(agg.failed_sessions, agg.total_sessions, agg.top_failure_reason),
            fix_action=_TLS_FIX_ACTIONS.get(agg.top_failure_reason) if has_failure else None,
            fix_category=_TLS_FIX_CATEGORY.get(agg.top_failure_reason) if has_failure else None,
        ))

    return TlsOverviewOut(
        domain=domain.name,
        mta_sts_stage=domain.mta_sts_stage,
        total_sessions=total,
        successful_sessions=successful,
        failed_sessions=failed,
        pass_pct=pass_pct,
        fail_groups=fail_groups,
        fail_types=_build_fail_types(aggs),
        mx_hosts=mx_hosts,
    )


@router.get("/record-diff", response_model=RecordDiffOut)
async def get_tls_record_diff(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domain = await _get_domain(domain_id, user.tenant_id, db)

    # Re-check live state before building the diff — domain.mta_sts_stage can
    # otherwise be stale (e.g. a policy was published manually outside the
    # app, or the DNS record exists but the stored stage never got synced),
    # which would mislabel an already-published policy as not yet existing.
    dns_check = await check_mta_sts_dns(domain.name)
    if dns_check["exists"]:
        domain.mta_sts_published = True
        policy = await fetch_mta_sts_policy(domain.name)
        if policy["reachable"] and policy["mode"] in ("enforce", "testing"):
            if domain.mta_sts_stage != policy["mode"]:
                domain.mta_sts_stage = policy["mode"]
                domain.mta_sts_policy_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        await db.commit()

    diff = generate_record_diff(domain)

    aggs = (await db.execute(select(TlsAggregate).where(TlsAggregate.domain_id == domain.id))).scalars().all()
    from app.models import SslCert
    certs = (await db.execute(select(SslCert).where(SslCert.domain_id == domain.id))).scalars().all()
    min_days = min((c.days_remaining for c in certs if c.days_remaining is not None), default=None)

    gates = [
        {"label": "All MX hosts support STARTTLS", "ok": all(c.starttls_supported for c in certs if c.host_type == "mx")},
        {"label": "Certificates valid and hostname-matched", "ok": all(c.hostname_valid and (c.days_remaining or 0) > 7 for c in certs)},
        {"label": "Zero TLS failures in testing window", "ok": sum(a.failed_sessions for a in aggs) == 0},
    ]
    if min_days and min_days < 30:
        gates.append({"label": f"Renew certificate ({min_days}d remaining) before enforcing", "ok": False})

    total_failures = sum(a.failed_sessions for a in aggs)
    failing_mx = [a.mx_host for a in aggs if a.failed_sessions > 0]
    fail_context = ""
    if failing_mx:
        fail_context = f" The {len(failing_mx)} MX host(s) with failures ({', '.join(failing_mx)}) need to be resolved first — check expired certificates or missing STARTTLS support on those hosts."

    return RecordDiffOut(
        host=diff["host"],
        current=diff["current"],
        proposed=diff["proposed"],
        why=(
            f"Once MTA-STS is set to enforce, any sending mail server that cannot negotiate a valid TLS connection "
            f"to your MX hosts will have its delivery attempt rejected — messages will not fall back to plaintext. "
            f"This protects your inbound mail from interception and downgrade attacks.{fail_context}"
        ),
        gates=gates,
        ready=all(g["ok"] for g in gates),
    )


@router.post("/mark-published")
async def mark_tls_published(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domain = await _get_domain(domain_id, user.tenant_id, db)
    domain.tlsrpt_record_published = True
    domain.mta_sts_published = True
    domain.mta_sts_stage = "testing"
    domain.mta_sts_policy_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    await db.commit()
    return {"ok": True}
