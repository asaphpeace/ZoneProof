import uuid as _uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.reported_email import ReportedEmail
from app.models.user import User
from app.routers.auth import _require_admin, _require_admin_or_approver, get_current_user
from app.schemas.reported_email import ReportedEmailOut, UnmaskReporterOut, UpdateDispositionRequest
from app.services import audit_service
from app.services.email_ingestion_service import unmask_reporter
from app.services.link_risk_service import score_report_urls_best_effort

router = APIRouter(tags=["phishing-reports"])

_VALID_DISPOSITIONS = {"new", "confirmed_malicious", "false_positive", "already_known"}


def _report_out(r: ReportedEmail) -> ReportedEmailOut:
    return ReportedEmailOut(
        id=str(r.id), received_at=r.received_at.isoformat(), reporter_hash=r.reporter_hash,
        original_subject=r.original_subject, original_from=r.original_from, original_from_domain=r.original_from_domain,
        original_date=r.original_date.isoformat() if r.original_date else None,
        body_text_excerpt=r.body_text_excerpt, urls_found=r.urls_found,
        is_original_message_attached=r.is_original_message_attached,
        spf_result=r.spf_result, dkim_result=r.dkim_result, dmarc_result=r.dmarc_result, auth_results_raw=r.auth_results_raw,
        disposition=r.disposition, disposition_note=r.disposition_note,
        disposition_at=r.disposition_at.isoformat() if r.disposition_at else None,
        url_risk=r.url_risk, url_risk_scored_at=r.url_risk_scored_at.isoformat() if r.url_risk_scored_at else None,
    )


def _risk_summary(r: ReportedEmail) -> dict:
    entries = r.url_risk or []
    return {
        "scored_count": len(entries),
        "dangerous_count": sum(1 for e in entries if e.get("verdict") == "likely_dangerous"),
    }


async def _get_owned_report(db: AsyncSession, user: User, report_id: str) -> ReportedEmail:
    try:
        rid = _uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Reported email not found")
    report = await db.get(ReportedEmail, rid)
    if not report or report.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Reported email not found")
    return report


@router.get("/reported-emails", response_model=list[ReportedEmailOut])
async def list_reported_emails(
    disposition: str | None = None, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    query = select(ReportedEmail).where(ReportedEmail.tenant_id == user.tenant_id)
    if disposition:
        query = query.where(ReportedEmail.disposition == disposition)
    result = await db.execute(query.order_by(ReportedEmail.received_at.desc()))
    return [_report_out(r) for r in result.scalars().all()]


@router.get("/reported-emails/{report_id}", response_model=ReportedEmailOut)
async def get_reported_email(report_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    report = await _get_owned_report(db, user, report_id)
    return _report_out(report)


@router.patch("/reported-emails/{report_id}/disposition", response_model=ReportedEmailOut)
async def update_disposition(
    report_id: str, payload: UpdateDispositionRequest, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    _require_admin_or_approver(user)
    if payload.disposition not in _VALID_DISPOSITIONS:
        raise HTTPException(status_code=400, detail=f"disposition must be one of {sorted(_VALID_DISPOSITIONS)}")
    report = await _get_owned_report(db, user, report_id)

    from datetime import datetime, timezone
    before = {"disposition": report.disposition, "disposition_note": report.disposition_note}
    report.disposition = payload.disposition
    report.disposition_note = payload.note
    report.disposition_by_user_id = user.id
    report.disposition_at = datetime.now(timezone.utc)

    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="reported_email.disposition_changed",
        target_type="reported_email", target_id=str(report.id), target_label=report.original_subject or "(no subject)",
        before=before, after={"disposition": report.disposition, "disposition_note": report.disposition_note},
    )
    await db.commit()
    await db.refresh(report)
    return _report_out(report)


@router.post("/reported-emails/{report_id}/rescan-links", response_model=ReportedEmailOut)
async def rescan_reported_email_links(report_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Forces a fresh scan bypassing the domain-age cache TTL — for a
    report that failed to score at ingestion time, or when an admin wants
    an up-to-date check (a domain's age tier or Web Risk status can
    change since first triaged). Same role bar as disposition changes —
    a benign re-check, not identity-revealing like unmask."""
    _require_admin_or_approver(user)
    report = await _get_owned_report(db, user, report_id)

    before = _risk_summary(report)
    await score_report_urls_best_effort(db, report, force_refresh=True)

    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="reported_email.links_rescanned",
        target_type="reported_email", target_id=str(report.id), target_label=report.original_subject or "(no subject)",
        before=before, after=_risk_summary(report),
    )
    await db.commit()
    await db.refresh(report)
    return _report_out(report)


@router.post("/reported-emails/{report_id}/unmask-reporter", response_model=UnmaskReporterOut)
async def unmask_reporter_route(report_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Admin-only, not admin-or-approver — reveals a real identity, same
    bar as phishing.unmask_recipient."""
    _require_admin(user)
    report = await _get_owned_report(db, user, report_id)
    email = await unmask_reporter(db, report)
    if not email:
        raise HTTPException(status_code=404, detail="No known target-list entry matches this reporter's hash")

    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="reported_email.reporter_unmasked",
        target_type="reported_email", target_id=str(report.id), target_label=email,
    )
    await db.commit()
    return UnmaskReporterOut(email=email)
