import csv
import io
import statistics
import uuid as _uuid
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import (
    Actor, ActorIdentity, Domain, Engagement, PhishingCampaign, PhishingCustomTemplate, PhishingEvent,
    PhishingExemption, PhishingTargetList, TrainingAssignment, TrainingCourse,
)
from app.models.user import Tenant, User
from app.rate_limit import limiter
from app.routers.auth import _require_admin, _require_admin_or_approver, get_current_user
from app.schemas.phishing import (
    DepartmentBreakdownOut, DepartmentTrainingOut, EmailAuthEvidenceOut, EngagementRecipientCampaignOut,
    EngagementRecipientOut, LandingPageOut, LaunchCampaignRequest, PhishingCampaignOut, PhishingCampaignSummaryOut,
    PhishingContentPreviewOut, PhishingCustomTemplateCreate, PhishingCustomTemplateOut, PhishingCustomTemplateUpdate,
    PhishingDashboardOut, PhishingEventCountsOut, PhishingExemptionCreate, PhishingExemptionOut, PhishingLureStatOut,
    PhishingMetaOut, PhishingTargetListCreate, PhishingTargetListOut, PhishingTemplateOut, PrivEscPathSummaryOut,
    RecipientEventDetailOut, RecipientEventsOut, RiskComponentOut, SendTestTemplateEmailRequest, TargetListDiffOut,
    TargetListDiffRequest, UnmaskOut, UnmaskRequest,
)
from app.services import audit_service, email_service
from app.services.identity_resolution_service import find_open_privesc_paths_for_principal
from app.services.phishing_evidence_service import get_email_auth_evidence
from app.services.phishing_lesson_content import _LESSON_CATEGORIES
from app.services.plan_limits import require_feature
from app.services.reporting_address import generate_slug, reporting_address
from app.services.training_course_service import compute_tenant_survey_sentiment_score
from app.services.phishing_service import (
    BUILT_IN_LANDING_PAGES, BUILT_IN_TEMPLATES, CustomTemplateNotLaunchable, _hash_recipient,
    compute_department_breakdown, compute_department_training_completion, compute_dwell_seconds,
    compute_human_risk_components, compute_tenant_human_risk_score, compute_tenant_phishing_summary,
    diff_target_list_entries, get_phishing_campaigns_summary, get_tenant_watchlist,
    is_target_list_training_ready, launch_campaign, resolve_campaign_content,
    unmask_recipient, validate_custom_template_for_launch,
)

router = APIRouter(tags=["phishing"])

_CREDENTIAL_CAPTURE_POLICY = "hashed — never stored in clear"
_RECIPIENT_PRIVACY_POLICY = "pseudonymous until admin unmask"


@router.get("/phishing-meta", response_model=PhishingMetaOut)
async def get_phishing_meta(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Real, tenant-scoped values for the Phishing Simulation screen's
    status bar — the sending/tracking domain actually in use, and whether
    this tenant's HALT ALL SENDS switch is currently on."""
    tenant = await db.get(Tenant, user.tenant_id)
    tracking_host = urlparse(settings.command_phishing_track_base_url).netloc or settings.command_phishing_track_base_url

    # Lazily provisioned — same slug format/generator as Domain.
    # reporting_slug, just tenant- not domain-scoped (Phishing Simulation
    # roadmap Phase 26). No "tenant created" hook to provision this
    # eagerly at, so the first real read of this endpoint does it instead.
    if tenant and not tenant.phishing_report_slug:
        tenant.phishing_report_slug = generate_slug()
        await db.commit()
        await db.refresh(tenant)

    return PhishingMetaOut(
        tracking_domain=tracking_host,
        # Every simulated send goes out from Sentinel's own verified
        # identity — never the customer's domain (phishing_service.py's
        # module docstring). Real value, not a per-tenant-spoofed sender.
        sending_identity=f"{settings.email_from_name} <{settings.email_from_address}>",
        credential_capture_policy=_CREDENTIAL_CAPTURE_POLICY,
        recipient_privacy_policy=_RECIPIENT_PRIVACY_POLICY,
        phishing_paused=bool(tenant and tenant.phishing_paused),
        phishing_report_schedule=tenant.phishing_report_schedule if tenant else "off",
        last_phishing_report_sent_at=tenant.last_phishing_report_sent_at.isoformat() if tenant and tenant.last_phishing_report_sent_at else None,
        auto_assign_training_course_id=str(tenant.auto_assign_training_course_id) if tenant and tenant.auto_assign_training_course_id else None,
        training_reminder_interval_days=tenant.training_reminder_interval_days if tenant else 14,
        training_reminder_max_count=tenant.training_reminder_max_count if tenant else 2,
        report_suspicious_email_address=reporting_address(tenant.phishing_report_slug) if tenant and tenant.phishing_report_slug else "",
    )


class UpdatePhishingReportScheduleRequest(BaseModel):
    schedule: str  # off | weekly | monthly


@router.patch("/phishing-meta/report-schedule", response_model=PhishingMetaOut)
async def update_phishing_report_schedule(
    payload: UpdatePhishingReportScheduleRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Mirrors billing.py's update_report_schedule exactly — same plan
    gate (scheduled_reports), same admin-only rule, same off|weekly|
    monthly values — for the phishing/Human-Risk PDF report instead of
    the DMARC/posture one."""
    _require_admin(user)
    if payload.schedule not in ("off", "weekly", "monthly"):
        raise HTTPException(status_code=400, detail="schedule must be off, weekly, or monthly")

    tenant = await db.get(Tenant, user.tenant_id)
    if payload.schedule != "off":
        require_feature(tenant, "scheduled_reports")

    tenant.phishing_report_schedule = payload.schedule
    await db.commit()
    return await get_phishing_meta(db, user)


class UpdateTrainingDefaultsRequest(BaseModel):
    # PATCH semantics (exclude_unset below) — only fields the caller
    # actually sends are changed, including an explicit null for
    # auto_assign_training_course_id to turn course-based training back off.
    auto_assign_training_course_id: str | None = None
    training_reminder_interval_days: int | None = None
    training_reminder_max_count: int | None = None


@router.patch("/phishing-meta/training-defaults", response_model=PhishingMetaOut)
async def update_training_defaults(
    payload: UpdateTrainingDefaultsRequest, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    _require_admin(user)
    tenant = await db.get(Tenant, user.tenant_id)
    updates = payload.model_dump(exclude_unset=True)

    if "auto_assign_training_course_id" in updates:
        raw = updates["auto_assign_training_course_id"]
        if raw is None:
            tenant.auto_assign_training_course_id = None
        else:
            try:
                course_uuid = _uuid.UUID(raw)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid course id")
            course = await db.get(TrainingCourse, course_uuid)
            if not course or course.tenant_id != user.tenant_id:
                raise HTTPException(status_code=400, detail="Unknown course id")
            tenant.auto_assign_training_course_id = course_uuid
    if "training_reminder_interval_days" in updates:
        if updates["training_reminder_interval_days"] < 1:
            raise HTTPException(status_code=400, detail="training_reminder_interval_days must be at least 1")
        tenant.training_reminder_interval_days = updates["training_reminder_interval_days"]
    if "training_reminder_max_count" in updates:
        if updates["training_reminder_max_count"] < 0:
            raise HTTPException(status_code=400, detail="training_reminder_max_count cannot be negative")
        tenant.training_reminder_max_count = updates["training_reminder_max_count"]

    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="phishing.training_defaults_updated",
        target_type="tenant", target_id=str(tenant.id), target_label=tenant.name,
    )
    await db.commit()
    return await get_phishing_meta(db, user)


@router.post("/phishing-meta/halt", response_model=PhishingMetaOut)
async def halt_all_phishing_sends(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Tenant-wide kill switch — blocks every future manual launch and the
    recurring scheduler for this tenant until resumed. Does not revoke or
    otherwise touch individual engagements. Admin-only, not admin-or-
    approver — this is stricter than launching a campaign on purpose."""
    _require_admin(user)
    tenant = await db.get(Tenant, user.tenant_id)
    tenant.phishing_paused = True
    await audit_service.log(db, tenant_id=user.tenant_id, actor=user, action="phishing.halt_all_sends", target_type="tenant", target_id=str(tenant.id), target_label=tenant.name)
    await db.commit()
    return await get_phishing_meta(db, user)


@router.post("/phishing-meta/resume", response_model=PhishingMetaOut)
async def resume_all_phishing_sends(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    _require_admin(user)
    tenant = await db.get(Tenant, user.tenant_id)
    tenant.phishing_paused = False
    await audit_service.log(db, tenant_id=user.tenant_id, actor=user, action="phishing.resume_all_sends", target_type="tenant", target_id=str(tenant.id), target_label=tenant.name)
    await db.commit()
    return await get_phishing_meta(db, user)


def _target_list_out(tl: PhishingTargetList) -> PhishingTargetListOut:
    return PhishingTargetListOut(id=str(tl.id), name=tl.name, entries=tl.entries, created_at=tl.created_at.isoformat())


def _campaign_out(c: PhishingCampaign) -> PhishingCampaignOut:
    return PhishingCampaignOut(
        id=str(c.id), engagement_id=str(c.engagement_id), target_list_id=str(c.target_list_id),
        template_id=c.template_id, status=c.status, launched_at=c.launched_at.isoformat(),
        llm_generated=c.llm_generated, subject_sent=c.subject_sent, dmarc_context=c.dmarc_context,
        body_html_sent=c.body_html_sent, landing_page_id=c.landing_page_id, audience_label=c.audience_label,
    )


@router.get("/phishing-landing-pages", response_model=list[LandingPageOut])
async def list_phishing_landing_pages(user: User = Depends(get_current_user)):
    """The real, selectable landing pages a click can show (Coverage Map
    plan phishing transformation, Phase 3) — every reference platform
    treats this as an explicit wizard step, not a hidden implementation
    detail."""
    return [LandingPageOut(id=pid, label=p["label"]) for pid, p in BUILT_IN_LANDING_PAGES.items()]


@router.get("/phishing-templates", response_model=list[PhishingTemplateOut])
async def list_phishing_templates(user: User = Depends(get_current_user)):
    """Real starting content for each built-in lure — the UI pre-fills an
    editable subject/body from this rather than customizing blind."""
    return [
        PhishingTemplateOut(
            id=tid, label=t["label"], category=t.get("category", "General"), subject=t["subject"], body_html=t["body_html"],
            teachable_signals=_LESSON_CATEGORIES.get(tid, _LESSON_CATEGORIES["generic"])["generic_flags"],
        )
        for tid, t in BUILT_IN_TEMPLATES.items()
    ]


def _custom_template_out(t: PhishingCustomTemplate, eligible: bool | None = None) -> PhishingCustomTemplateOut:
    return PhishingCustomTemplateOut(
        id=str(t.id), label=t.label, category=t.category, subject=t.subject, body_html=t.body_html,
        difficulty=t.difficulty, from_email=t.from_email, display_name=t.display_name,
        include_attachments=t.include_attachments, created_at=t.created_at.isoformat(), updated_at=t.updated_at.isoformat(),
        eligible=eligible,
    )


@router.get("/phishing-custom-templates", response_model=list[PhishingCustomTemplateOut])
async def list_custom_templates(
    target_list_id: str | None = None, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    """Tenant-owned, reusable templates — separate from the fixed built-in
    catalog above. Newest first, so the template someone's actively
    iterating on surfaces at the top of the gallery.

    target_list_id is optional — when passed, each medium/high-difficulty
    template's `eligible` field reflects whether that real audience has
    the training track record to unlock it (is_target_list_training_ready,
    also independently re-checked server-side at launch, not just here)."""
    result = await db.execute(
        select(PhishingCustomTemplate).where(PhishingCustomTemplate.tenant_id == user.tenant_id)
        .order_by(PhishingCustomTemplate.updated_at.desc())
    )
    templates = result.scalars().all()

    training_ready: bool | None = None
    if target_list_id and any(t.difficulty in ("medium", "high") for t in templates):
        target_list = await db.get(PhishingTargetList, target_list_id)
        if target_list and target_list.tenant_id == user.tenant_id:
            training_ready = await is_target_list_training_ready(db, user.tenant_id, target_list)

    def _eligible_for(t: PhishingCustomTemplate) -> bool | None:
        if not target_list_id:
            return None
        if t.difficulty == "low":
            return True
        return bool(training_ready)

    return [_custom_template_out(t, eligible=_eligible_for(t)) for t in templates]


@router.post("/phishing-custom-templates", response_model=PhishingCustomTemplateOut, status_code=201)
async def create_custom_template(
    payload: PhishingCustomTemplateCreate, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    t = PhishingCustomTemplate(id=_uuid.uuid4(), tenant_id=user.tenant_id, **payload.model_dump())
    db.add(t)
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="phishing.custom_template_created",
        target_type="phishing_custom_template", target_id=str(t.id), target_label=t.label,
    )
    await db.commit()
    await db.refresh(t)
    return _custom_template_out(t)


async def _get_owned_custom_template(db: AsyncSession, user: User, template_id: str) -> PhishingCustomTemplate:
    try:
        tid = _uuid.UUID(template_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Template not found")
    t = await db.get(PhishingCustomTemplate, tid)
    if not t or t.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Template not found")
    return t


@router.patch("/phishing-custom-templates/{template_id}", response_model=PhishingCustomTemplateOut)
async def update_custom_template(
    template_id: str, payload: PhishingCustomTemplateUpdate,
    db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    t = await _get_owned_custom_template(db, user, template_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(t, field, value)
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="phishing.custom_template_updated",
        target_type="phishing_custom_template", target_id=str(t.id), target_label=t.label,
    )
    await db.commit()
    await db.refresh(t)
    return _custom_template_out(t)


@router.delete("/phishing-custom-templates/{template_id}", status_code=204)
async def delete_custom_template(template_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    t = await _get_owned_custom_template(db, user, template_id)
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="phishing.custom_template_deleted",
        target_type="phishing_custom_template", target_id=str(t.id), target_label=t.label,
    )
    await db.delete(t)
    await db.commit()


@router.post("/phishing-templates/send-test", status_code=204)
async def send_test_template_email(
    payload: SendTestTemplateEmailRequest, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    """Sends the draft being edited — saved or not — to the requesting
    admin's own inbox, so they can see real client rendering before this
    ever reaches a real recipient. Never creates a PhishingEvent or a real
    tracking token: {click_url}/{report_url} are replaced with a plainly
    inert placeholder rather than a live tracked link, so a self-test can
    never be mistaken for — or pollute the evidence of — a real campaign."""
    body_html = (
        payload.body_html
        .replace("{click_url}", "#test-send-not-a-real-tracked-link")
        .replace("{report_url}", "#test-send-not-a-real-tracked-link")
    )
    sent = await email_service.send_email(
        db, to=user.email, subject=f"[TEST SEND] {payload.subject}", body_html=body_html,
        text_body="This is a test send of a phishing simulation template — no click or open here is tracked.",
    )
    if not sent:
        raise HTTPException(status_code=502, detail="Test send failed — check SENDGRID_API_KEY and sender verification.")


def _score_to_grade(score: float) -> str:
    # Mirrors app/routers/overview.py's _score_to_grade exactly — same
    # thresholds, kept as a small local copy rather than a cross-router
    # import since both are private, stable, and trivial.
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


@router.get("/phishing-dashboard", response_model=PhishingDashboardOut)
async def get_phishing_dashboard(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Real, tenant-wide phishing/awareness posture — every number here is
    either computed live from real campaign history or explicitly None.
    Human risk score already existed as one input to the composite
    Sentinel Score on the Overview page; this is the first place it's
    shown on its own."""
    summary = await compute_tenant_phishing_summary(db, user.tenant_id)
    score = await compute_tenant_human_risk_score(db, user.tenant_id)
    department_training = await compute_department_training_completion(db, user.tenant_id)
    sentiment_score = await compute_tenant_survey_sentiment_score(db, user.tenant_id)
    risk_components = compute_human_risk_components(summary, sentiment_score)
    watchlist = await get_tenant_watchlist(db, user.tenant_id)

    if summary is None:
        return PhishingDashboardOut(
            risk_components=[RiskComponentOut(**c) for c in risk_components],
            department_training=[DepartmentTrainingOut(**d) for d in department_training],
            watchlist=[EngagementRecipientOut(**w) for w in watchlist],
        )

    return PhishingDashboardOut(
        human_risk_score=score, human_risk_grade=_score_to_grade(score) if score is not None else None,
        risk_components=[RiskComponentOut(**c) for c in risk_components],
        sent=summary["sent"], click_rate=summary["click_rate"], credential_rate=summary["credential_rate"],
        report_rate=summary["report_rate"], training_assigned=summary["training_assigned"],
        training_completed=summary["training_completed"], training_completion_rate=summary["training_completion_rate"],
        course_training_assigned=summary["course_training_assigned"], course_training_completed=summary["course_training_completed"],
        course_training_completion_rate=summary["course_training_completion_rate"],
        department_training=[DepartmentTrainingOut(**d) for d in department_training],
        watchlist=[EngagementRecipientOut(**w) for w in watchlist],
    )


@router.get("/phishing-lure-stats", response_model=list[PhishingLureStatOut])
async def get_phishing_lure_stats(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Real per-lure click-rate history across every campaign this tenant
    has ever launched (Phishing Simulation roadmap Phase 16) — surfaced in
    the wizard's template gallery so a lure is picked with real data, not
    guessed. Only templates this tenant has actually sent appear; an unused
    template is simply absent from the response, never a fabricated 0%."""
    result = await db.execute(
        select(PhishingCampaign.template_id, PhishingEvent.event_type, func.count())
        .join(PhishingEvent, PhishingEvent.campaign_id == PhishingCampaign.id)
        .where(PhishingCampaign.tenant_id == user.tenant_id)
        .group_by(PhishingCampaign.template_id, PhishingEvent.event_type)
    )
    counts: dict[str, dict[str, int]] = {}
    for template_id, event_type, count in result.all():
        counts.setdefault(template_id, {})[event_type] = count

    return [
        PhishingLureStatOut(
            template_id=template_id,
            sent_count=by_type.get("sent", 0),
            click_rate=(by_type.get("clicked", 0) / by_type["sent"]) if by_type.get("sent") else None,
        )
        for template_id, by_type in counts.items()
    ]


@router.get("/phishing-campaigns/summary", response_model=list[PhishingCampaignSummaryOut])
async def get_phishing_campaigns_summary_route(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Every campaign this tenant has ever launched, pre-aggregated with its
    own event counts, in one call (Phishing Simulation roadmap Phase 29b) —
    what the landing page's stat row and simulations table are built from.
    Registered before the /phishing-campaigns/{campaign_id} routes below so
    'summary' is never captured as a campaign_id path param."""
    rows = await get_phishing_campaigns_summary(db, user.tenant_id)
    return [PhishingCampaignSummaryOut(**row) for row in rows]


@router.post("/phishing-target-lists", response_model=PhishingTargetListOut)
async def create_target_list(
    payload: PhishingTargetListCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    target_list = PhishingTargetList(
        id=_uuid.uuid4(), tenant_id=user.tenant_id, name=payload.name,
        entries=[e.model_dump() for e in payload.entries],
    )
    db.add(target_list)
    # Real gap, found and closed (Phishing Simulation roadmap — live E2E
    # simulation pass): this defines exactly who a future real send can
    # target — real names/emails/departments — yet had no audit trail at
    # all, unlike everything downstream of it (approval, launch, unmask).
    # Never log the real entries themselves here, only the count — the
    # entries are the PII this module otherwise goes out of its way to
    # pseudonymize everywhere else.
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="phishing.target_list_created",
        target_type="phishing_target_list", target_id=str(target_list.id), target_label=target_list.name,
        after={"entry_count": len(target_list.entries)},
    )
    await db.commit()
    await db.refresh(target_list)
    return _target_list_out(target_list)


@router.get("/phishing-target-lists", response_model=list[PhishingTargetListOut])
async def list_target_lists(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    result = await db.execute(
        select(PhishingTargetList).where(PhishingTargetList.tenant_id == user.tenant_id).order_by(PhishingTargetList.created_at.desc())
    )
    return [_target_list_out(tl) for tl in result.scalars().all()]


@router.put("/phishing-target-lists/{target_list_id}", response_model=PhishingTargetListOut)
async def update_target_list(
    target_list_id: str,
    payload: PhishingTargetListCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """The re-read-fresh-each-cycle design (PHISHING_DESIGN.md Section 3.2)
    depends on customers being able to edit a list between campaigns —
    this is that edit path."""
    result = await db.execute(
        select(PhishingTargetList).where(PhishingTargetList.id == target_list_id, PhishingTargetList.tenant_id == user.tenant_id)
    )
    target_list = result.scalar_one_or_none()
    if not target_list:
        raise HTTPException(status_code=404, detail="Target list not found")

    before_count = len(target_list.entries)
    target_list.name = payload.name
    target_list.entries = [e.model_dump() for e in payload.entries]
    # Same gap-closing as create_target_list above — counts only, never the
    # real entries themselves, in the audit trail.
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="phishing.target_list_updated",
        target_type="phishing_target_list", target_id=str(target_list.id), target_label=target_list.name,
        before={"entry_count": before_count}, after={"entry_count": len(target_list.entries)},
    )
    await db.commit()
    await db.refresh(target_list)
    return _target_list_out(target_list)


@router.post("/phishing-target-lists/{target_list_id}/diff", response_model=TargetListDiffOut)
async def diff_target_list(
    target_list_id: str, payload: TargetListDiffRequest, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    """Preview-only — never writes anything. A re-uploaded CSV is diffed
    against this list's real current entries (Phishing Simulation roadmap
    Phase 25) so a customer can see exactly what an upload would change
    before committing to it via the existing PUT above, rather than
    silently overwriting the list or requiring a manual side-by-side
    comparison."""
    result = await db.execute(
        select(PhishingTargetList).where(PhishingTargetList.id == target_list_id, PhishingTargetList.tenant_id == user.tenant_id)
    )
    target_list = result.scalar_one_or_none()
    if not target_list:
        raise HTTPException(status_code=404, detail="Target list not found")

    diff = diff_target_list_entries(target_list.entries, [e.model_dump() for e in payload.entries])
    return TargetListDiffOut(**diff)


def _exemption_out(ex: PhishingExemption) -> PhishingExemptionOut:
    return PhishingExemptionOut(id=str(ex.id), email=ex.email, reason=ex.reason, created_at=ex.created_at.isoformat())


@router.get("/phishing-exemptions", response_model=list[PhishingExemptionOut])
async def list_phishing_exemptions(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    result = await db.execute(
        select(PhishingExemption).where(PhishingExemption.tenant_id == user.tenant_id).order_by(PhishingExemption.created_at.desc())
    )
    return [_exemption_out(ex) for ex in result.scalars().all()]


@router.post("/phishing-exemptions", response_model=PhishingExemptionOut, status_code=201)
async def create_phishing_exemption(
    payload: PhishingExemptionCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Admin-only, not admin-or-approver — an exemption is a compliance/
    legal control, a different kind of decision than authorizing a
    campaign. Enforced at audience-resolution time in
    launch_phishing_campaign(), not just hidden from target-list UI."""
    _require_admin(user)
    email = payload.email.strip().lower()
    existing = await db.scalar(
        select(PhishingExemption).where(PhishingExemption.tenant_id == user.tenant_id, PhishingExemption.email == email)
    )
    if existing:
        return _exemption_out(existing)
    exemption = PhishingExemption(
        id=_uuid.uuid4(), tenant_id=user.tenant_id, email=email, reason=payload.reason, created_by_user_id=user.id,
    )
    db.add(exemption)
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="phishing.exemption_added",
        target_type="phishing_exemption", target_id=str(exemption.id), target_label=email,
    )
    await db.commit()
    await db.refresh(exemption)
    return _exemption_out(exemption)


@router.delete("/phishing-exemptions/{exemption_id}", status_code=204)
async def delete_phishing_exemption(exemption_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    _require_admin(user)
    result = await db.execute(
        select(PhishingExemption).where(PhishingExemption.id == exemption_id, PhishingExemption.tenant_id == user.tenant_id)
    )
    exemption = result.scalar_one_or_none()
    if not exemption:
        raise HTTPException(status_code=404, detail="Exemption not found")
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="phishing.exemption_removed",
        target_type="phishing_exemption", target_id=str(exemption.id), target_label=exemption.email,
    )
    await db.delete(exemption)
    await db.commit()


async def _get_phishing_engagement(engagement_id: str, db: AsyncSession, user: User) -> Engagement:
    result = await db.execute(
        select(Engagement).where(
            Engagement.id == engagement_id, Engagement.tenant_id == user.tenant_id, Engagement.tier == "phishing",
        )
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(status_code=404, detail="Phishing engagement not found")
    return engagement


@router.post("/engagements/{engagement_id}/phishing-content-preview", response_model=PhishingContentPreviewOut)
@limiter.limit("10/minute")
async def preview_phishing_content(
    request: Request,
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generates (or resolves the static override for) this engagement's
    next-cycle content WITHOUT sending anything or creating a campaign row
    — the mandatory human-review-before-send step (Coverage Map plan
    Phase 7). Works regardless of the engagement's authorization status,
    since content should be reviewable before a signature is even
    requested. The caller must pass this response back verbatim as
    LaunchCampaignRequest to guarantee what was reviewed is what sends."""
    engagement = await _get_phishing_engagement(engagement_id, db, user)
    scope = engagement.scope or {}
    target_list_id = scope.get("target_list_id")
    template_id = scope.get("template_id")
    if not target_list_id or not template_id:
        raise HTTPException(status_code=400, detail="Engagement scope is missing target_list_id or template_id")

    result = await db.execute(
        select(PhishingTargetList).where(PhishingTargetList.id == target_list_id, PhishingTargetList.tenant_id == user.tenant_id)
    )
    target_list = result.scalar_one_or_none()
    if not target_list:
        raise HTTPException(status_code=400, detail="target_list_id in engagement scope does not resolve to a target list")

    tenant = await db.get(Tenant, user.tenant_id)
    subject, body_html, llm_generated, dmarc_context = await resolve_campaign_content(
        db, user.tenant_id, target_list, template_id,
        scope.get("subject_override"), scope.get("body_html_override"),
        bool(scope.get("llm_generate_fresh")), tenant.name if tenant else "your organization",
    )
    if not subject or not body_html:
        raise HTTPException(status_code=400, detail="No content to preview — this template has no subject/body")
    return PhishingContentPreviewOut(subject=subject, body_html=body_html, llm_generated=llm_generated, dmarc_context=dmarc_context)


@router.post("/engagements/{engagement_id}/phishing-campaigns", response_model=PhishingCampaignOut)
@limiter.limit("5/minute")
async def launch_phishing_campaign(
    request: Request,
    engagement_id: str,
    payload: LaunchCampaignRequest = LaunchCampaignRequest(),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Launches immediately, using the target_list_id/template_id/
    cadence_days already recorded in the engagement's scope at creation —
    the same fields the recurring scheduler reads (PHISHING_DESIGN.md
    Section 3.3). Requires 'active', which for tier='phishing' can only be
    reached via the real Dropbox Sign signature flow — no auto-approve
    bypass for this tier, unlike Tier A. If payload carries
    approved_subject/approved_body_html (from the preview endpoint above),
    that exact content ships instead of generating again."""
    _require_admin_or_approver(user)
    engagement = await _get_phishing_engagement(engagement_id, db, user)
    if engagement.status != "active":
        raise HTTPException(status_code=400, detail=f"Engagement is '{engagement.status}', not 'active' — it must be signed before a campaign can launch")

    tenant = await db.get(Tenant, user.tenant_id)
    if tenant and tenant.phishing_paused:
        raise HTTPException(status_code=400, detail="HALT ALL SENDS is active for this tenant — resume sends before launching a campaign")

    scope = engagement.scope or {}
    target_list_id = scope.get("target_list_id")
    template_id = scope.get("template_id")
    if not target_list_id or not template_id:
        raise HTTPException(status_code=400, detail="Engagement scope is missing target_list_id or template_id")

    result = await db.execute(
        select(PhishingTargetList).where(PhishingTargetList.id == target_list_id, PhishingTargetList.tenant_id == user.tenant_id)
    )
    target_list = result.scalar_one_or_none()
    if not target_list:
        raise HTTPException(status_code=400, detail="target_list_id in engagement scope does not resolve to a target list")

    # A non-built-in template_id may be a real, tenant-owned custom
    # template (Phishing Simulation roadmap Phase 23) — validated the same
    # way the recurring scheduler validates it on every cycle, not a
    # one-off inline check (see validate_custom_template_for_launch).
    try:
        await validate_custom_template_for_launch(db, user.tenant_id, template_id, target_list, bool(scope.get("llm_generate_fresh")))
    except CustomTemplateNotLaunchable as e:
        raise HTTPException(status_code=400, detail=str(e))

    approved_content = None
    if payload.approved_subject and payload.approved_body_html:
        approved_content = (
            payload.approved_subject, payload.approved_body_html,
            payload.approved_llm_generated, payload.approved_dmarc_context,
        )

    # Audience scoping (Phishing Simulation roadmap Phase 15) — resolved
    # here, not in launch_campaign(), which only knows how to send to
    # whichever entries it's handed. "everyone" (default) is unchanged
    # behavior: no override, no label.
    entries_override: list[dict] | None = None
    audience_label: str | None = None
    if payload.audience_type == "department":
        if not payload.department:
            raise HTTPException(status_code=400, detail="audience_type='department' requires a department")
        entries_override = [e for e in target_list.entries if e.get("department") == payload.department]
        if not entries_override:
            raise HTTPException(status_code=400, detail=f"No one in target list '{target_list.name}' has department '{payload.department}'")
        audience_label = f"{payload.department} department ({len(entries_override)} of {len(target_list.entries)})"
    elif payload.audience_type == "individual":
        if not payload.recipient_hashes:
            raise HTTPException(status_code=400, detail="audience_type='individual' requires recipient_hashes")
        wanted = set(payload.recipient_hashes)
        entries_override = [
            e for e in target_list.entries
            if e.get("email") and _hash_recipient(e["email"], engagement.tenant_id) in wanted
        ]
        if not entries_override:
            raise HTTPException(status_code=400, detail="None of the selected recipients match the current target list — it may have changed")
        audience_label = f"{len(entries_override)} individually selected recipient{'s' if len(entries_override) != 1 else ''}"

    # Exemptions apply after audience scoping, regardless of audience_type
    # or which target list an address came from (PhishingExemption is
    # tenant-wide, not per-list) — checked here so a re-added or
    # differently-spelled-case address can never bypass it.
    exempted_result = await db.execute(select(PhishingExemption.email).where(PhishingExemption.tenant_id == user.tenant_id))
    exempted_emails = {e.lower() for e in exempted_result.scalars().all()}
    if exempted_emails:
        base_entries = entries_override if entries_override is not None else target_list.entries
        filtered_entries = [e for e in base_entries if (e.get("email") or "").strip().lower() not in exempted_emails]
        excluded_count = len(base_entries) - len(filtered_entries)
        if excluded_count:
            if not filtered_entries:
                raise HTTPException(status_code=400, detail="Every recipient in this audience is on the phishing exemption list")
            entries_override = filtered_entries
            audience_label = f"{audience_label or 'everyone'} ({excluded_count} exempted excluded)"

    campaign = await launch_campaign(
        db, engagement, target_list, template_id,
        subject_override=scope.get("subject_override"), body_html_override=scope.get("body_html_override"),
        use_llm=bool(scope.get("llm_generate_fresh")), company_name=tenant.name if tenant else "your organization",
        approved_content=approved_content, landing_page_id=scope.get("landing_page_id"),
        entries_override=entries_override, audience_label=audience_label,
    )
    # Real employees are targeted by this action — independently reviewable
    # after the fact, same bar as every other consequential action here.
    real_recipient_count = len(entries_override) if entries_override is not None else len(target_list.entries)
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="phishing.campaign_launched",
        target_type="phishing_campaign", target_id=str(campaign.id), target_label=template_id,
        after={"recipient_count": real_recipient_count, "audience": audience_label or "everyone", "llm_generated": campaign.llm_generated},
    )
    await db.commit()
    return _campaign_out(campaign)


@router.get("/engagements/{engagement_id}/phishing-campaigns", response_model=list[PhishingCampaignOut])
async def list_phishing_campaigns(
    engagement_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    """History for one engagement — every past cycle, whether launched
    manually or by the recurring scheduler, since there's otherwise no way
    for a UI to discover a campaign id without already knowing it."""
    engagement = await _get_phishing_engagement(engagement_id, db, user)
    result = await db.execute(
        select(PhishingCampaign).where(PhishingCampaign.engagement_id == engagement.id).order_by(PhishingCampaign.launched_at.desc())
    )
    return [_campaign_out(c) for c in result.scalars().all()]


@router.get("/engagements/{engagement_id}/phishing-recipients", response_model=list[EngagementRecipientOut])
async def get_engagement_recipients(
    engagement_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    """Cross-campaign per-person view (Phishing Simulation roadmap Phase
    13) — one row per recipient_hash, aggregating their event history
    across every campaign this engagement has ever launched, so a repeat
    clicker is visible as a pattern rather than reset each cycle. Still
    pseudonymized by construction."""
    engagement = await _get_phishing_engagement(engagement_id, db, user)
    campaigns_result = await db.execute(
        select(PhishingCampaign).where(PhishingCampaign.engagement_id == engagement.id)
    )
    campaigns = {c.id: c for c in campaigns_result.scalars().all()}
    if not campaigns:
        return []

    events_result = await db.execute(
        select(PhishingEvent).where(PhishingEvent.campaign_id.in_(campaigns.keys())).order_by(PhishingEvent.occurred_at)
    )
    by_recipient: dict[str, list[PhishingEvent]] = {}
    for event in events_result.scalars().all():
        by_recipient.setdefault(event.recipient_hash, []).append(event)

    training_result = await db.execute(
        select(TrainingAssignment)
        .where(TrainingAssignment.campaign_id.in_(campaigns.keys()))
        .order_by(TrainingAssignment.assigned_at)
    )
    training_by_recipient: dict[str, list[TrainingAssignment]] = {}
    for t in training_result.scalars().all():
        training_by_recipient.setdefault(t.recipient_hash, []).append(t)

    out = []
    for h, events in by_recipient.items():
        by_campaign: dict[_uuid.UUID, list[PhishingEvent]] = {}
        for e in events:
            by_campaign.setdefault(e.campaign_id, []).append(e)

        campaign_summaries = sorted(
            (
                EngagementRecipientCampaignOut(
                    campaign_id=str(cid), launched_at=campaigns[cid].launched_at.isoformat(),
                    event_types=sorted({e.event_type for e in evs}),
                )
                for cid, evs in by_campaign.items()
            ),
            key=lambda c: c.launched_at,
        )
        trainings = training_by_recipient.get(h, [])

        out.append(EngagementRecipientOut(
            recipient_hash=h,
            campaigns=campaign_summaries,
            event_types=sorted({e.event_type for e in events}),
            repeat_click_count=sum(1 for evs in by_campaign.values() if any(e.event_type == "clicked" for e in evs)),
            training_status=trainings[-1].status if trainings else None,
        ))
    return out


async def _get_campaign(campaign_id: str, db: AsyncSession, user: User) -> PhishingCampaign:
    result = await db.execute(
        select(PhishingCampaign).where(PhishingCampaign.id == campaign_id, PhishingCampaign.tenant_id == user.tenant_id)
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.get("/phishing-campaigns/{campaign_id}", response_model=PhishingCampaignOut)
async def get_campaign(campaign_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    return _campaign_out(await _get_campaign(campaign_id, db, user))


@router.get("/phishing-campaigns/{campaign_id}/email-auth-evidence", response_model=EmailAuthEvidenceOut | None)
async def get_campaign_email_auth_evidence(
    campaign_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    """Independent evidence (Coverage Map plan phishing transformation,
    Phase 6) — real DMARC aggregate volume + Sentinel's own spoof-test
    result for the domain this campaign's simulation ran against. Computed
    live, not a launch-time snapshot, so it's always current. Same primary-
    domain resolution `_dmarc_context_for_tenant()` already uses, for
    consistency with the dmarc_context note already on the campaign."""
    campaign = await _get_campaign(campaign_id, db, user)
    domain_result = await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
        .order_by(Domain.ownership_verified.desc()).limit(1)
    )
    domain = domain_result.scalar_one_or_none()
    evidence = await get_email_auth_evidence(db, user.tenant_id, domain.id if domain else None, campaign.launched_at)
    return EmailAuthEvidenceOut(**evidence) if evidence else None


@router.get("/phishing-campaigns/{campaign_id}/events", response_model=PhishingEventCountsOut)
async def get_campaign_events(campaign_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Aggregate counts by default — per-recipient identity is only ever
    exposed via the explicit, audited unmask call below."""
    campaign = await _get_campaign(campaign_id, db, user)
    result = await db.execute(
        select(PhishingEvent.event_type, func.count())
        .where(PhishingEvent.campaign_id == campaign.id)
        .group_by(PhishingEvent.event_type)
    )
    counts = {event_type: count for event_type, count in result.all()}

    training_result = await db.execute(
        select(TrainingAssignment.status, func.count())
        .where(TrainingAssignment.campaign_id == campaign.id)
        .group_by(TrainingAssignment.status)
    )
    training_counts = {status: count for status, count in training_result.all()}
    counts["training_assigned"] = sum(training_counts.values())
    counts["training_completed"] = training_counts.get("completed", 0)

    all_events_result = await db.execute(
        select(PhishingEvent).where(PhishingEvent.campaign_id == campaign.id)
    )
    events_by_recipient: dict[str, list[PhishingEvent]] = {}
    for event in all_events_result.scalars().all():
        events_by_recipient.setdefault(event.recipient_hash, []).append(event)
    dwell_values = [
        d for d in (compute_dwell_seconds(events) for events in events_by_recipient.values()) if d is not None
    ]
    counts["median_dwell_seconds"] = statistics.median(dwell_values) if dwell_values else None
    return PhishingEventCountsOut(**counts)


@router.get("/phishing-campaigns/{campaign_id}/department-breakdown", response_model=list[DepartmentBreakdownOut])
async def get_campaign_department_breakdown(campaign_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Real, server-side-aggregated department results for one campaign —
    see compute_department_breakdown()'s docstring for the privacy
    discipline (recipient_hash never mapped to department in the API
    response, only aggregate counts)."""
    campaign = await _get_campaign(campaign_id, db, user)
    breakdown = await compute_department_breakdown(db, campaign)
    return [DepartmentBreakdownOut(**b) for b in breakdown]


@router.get("/phishing-campaigns/{campaign_id}/events/by-recipient", response_model=list[RecipientEventsOut])
async def get_campaign_events_by_recipient(
    campaign_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    """Still pseudonymized — lists which hashes exist and what happened for
    each, so an admin has something to pick from before calling the actual
    unmask endpoint below. Never returns an email or display_name."""
    campaign = await _get_campaign(campaign_id, db, user)
    result = await db.execute(
        select(PhishingEvent).where(PhishingEvent.campaign_id == campaign.id).order_by(PhishingEvent.occurred_at)
    )
    by_recipient: dict[str, list[PhishingEvent]] = {}
    for event in result.scalars().all():
        by_recipient.setdefault(event.recipient_hash, []).append(event)

    training_result = await db.execute(
        select(TrainingAssignment).where(TrainingAssignment.campaign_id == campaign.id)
    )
    training_by_recipient = {t.recipient_hash: t for t in training_result.scalars().all()}

    return [
        RecipientEventsOut(
            recipient_hash=h,
            event_types=[e.event_type for e in events],
            events=[
                RecipientEventDetailOut(
                    event_type=e.event_type, occurred_at=e.occurred_at.isoformat(),
                    ip_address=e.ip_address, user_agent=e.user_agent, destination_url=e.destination_url,
                )
                for e in events
            ],
            training_status=training_by_recipient[h].status if h in training_by_recipient else None,
            training_completed_at=(
                training_by_recipient[h].completed_at.isoformat()
                if h in training_by_recipient and training_by_recipient[h].completed_at else None
            ),
            dwell_seconds=compute_dwell_seconds(events),
        )
        for h, events in by_recipient.items()
    ]


@router.get("/phishing-campaigns/{campaign_id}/export.csv")
async def export_campaign_events(
    campaign_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    """CSV export of the campaign's real per-event evidence — the same
    who/what/when/where/destination data the Evidence report renders,
    for a customer or compliance handoff (Coverage Map plan phishing
    transformation, Phase 5, mirroring the audit-log export pattern in
    app/routers/audit.py). Recipients stay hashed here, same as
    everywhere else — unmasking is a separate, audited, admin-only
    action, not something a bulk export should shortcut."""
    campaign = await _get_campaign(campaign_id, db, user)
    result = await db.execute(
        select(PhishingEvent).where(PhishingEvent.campaign_id == campaign.id).order_by(PhishingEvent.occurred_at)
    )
    events = result.scalars().all()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["recipient_hash", "event_type", "occurred_at", "ip_address", "destination_url"])
    for e in events:
        writer.writerow([e.recipient_hash, e.event_type, e.occurred_at.isoformat(), e.ip_address or "", e.destination_url or ""])
    buffer.seek(0)

    filename = f"phishing-campaign-{campaign.launched_at.date().isoformat()}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/phishing-campaigns/{campaign_id}/events/unmask", response_model=UnmaskOut)
async def unmask_event(
    campaign_id: str,
    payload: UnmaskRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_admin(user)  # stricter than admin-or-approver on purpose — reveals a real identity

    campaign = await _get_campaign(campaign_id, db, user)
    identity = await unmask_recipient(db, campaign, payload.recipient_hash)
    if not identity:
        raise HTTPException(status_code=404, detail="No recipient in this campaign's target list matches that hash")

    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="phishing.recipient_unmasked",
        target_type="phishing_campaign", target_id=str(campaign.id), target_label=identity["email"],
    )

    # Privilege-correlated blast radius (Coverage Map plan phishing
    # transformation, Phase 8) — turns "who clicked" into "who clicked AND
    # has admin access to production." Honest by construction: an email
    # with no resolved AWS identity yields an empty list and a None
    # provenance, never a guess presented as fact.
    provenance: str | None = None
    actor = await db.scalar(select(Actor).where(Actor.tenant_id == user.tenant_id, Actor.email == identity["email"]))
    if actor:
        aws_identity = await db.scalar(
            select(ActorIdentity).where(
                ActorIdentity.tenant_id == user.tenant_id, ActorIdentity.actor_id == actor.id,
                ActorIdentity.source == "aws_iam",
            )
        )
        if aws_identity:
            provenance = aws_identity.email_provenance
    paths = await find_open_privesc_paths_for_principal(db, user.tenant_id, email=identity["email"])

    await db.commit()
    return UnmaskOut(
        **identity, cloud_identity_provenance=provenance,
        open_privesc_paths=[
            PrivEscPathSummaryOut(
                id=str(p.id), source_principal_arn=p.source_principal_arn, target_principal_arn=p.target_principal_arn,
                technique_chain=p.technique_chain, severity=p.severity,
            )
            for p in paths
        ],
    )
