"""
Training course library service (Phishing Simulation roadmap Phase 24).
Two access surfaces: an authenticated admin/approver surface (create
courses, assign them to an audience) and an unauthenticated recipient
surface (view/complete a course via its access_token — same
no-JS-required, silent-on-unknown-token discipline phishing_track.py's
routes already establish, since this is reached the same way, a link in
an email opened in whatever browser the recipient has).
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.phishing import PhishingCampaign, PhishingTargetList
from app.models.training_course import TrainingCourse, TrainingCourseAssignment, TrainingCourseModule
from app.models.user import Tenant
from app.services.email_service import send_email
from app.services.phishing_service import _hash_recipient

# Fixed, not admin-authored — the roadmap's explicit scope for the culture
# survey ("fixed questions only, not open-ended"), so a tenant can title a
# survey module but never collect arbitrary free-text sentiment data this
# product hasn't reviewed. 3-point scale, kept deliberately short (v1).
SURVEY_QUESTIONS = [
    {
        "key": "report_comfort",
        "label": "I feel comfortable reporting a suspicious email, even if I'm not sure it's actually malicious.",
    },
    {
        "key": "know_who_to_contact",
        "label": "I know who to contact if I think I've been targeted by a real phishing attempt.",
    },
    {
        "key": "shared_responsibility",
        "label": "Security feels like a shared responsibility on my team, not just IT's job.",
    },
    {
        "key": "blame_safety",
        "label": "I wouldn't feel embarrassed reporting it if I clicked a phishing link, even a simulated one.",
    },
]
_SURVEY_OPTIONS = [("agree", "Agree"), ("neutral", "Neutral"), ("disagree", "Disagree")]

# Every SURVEY_QUESTIONS statement above is phrased so "agree" is the
# positive/desired answer — this mapping only holds because of that.
_SENTIMENT_VALUE = {"agree": 100.0, "neutral": 50.0, "disagree": 0.0}


async def compute_tenant_survey_sentiment_score(db: AsyncSession, tenant_id: uuid.UUID) -> float | None:
    """The real-data input behind the Dashboard's 'Culture' risk component
    (Phishing Simulation roadmap Phase 30a) — averaged per-question first,
    then across questions, so one heavily-answered question can't drown out
    the others. None (never a fabricated score) when nobody has answered
    anything yet, which will be the common case for any tenant that hasn't
    built a survey-module course and gotten real completions — the same
    'not enough data yet' honesty get_survey_results() already applies to
    per-question aggregates, extended to a single overall score."""
    result = await db.execute(
        select(TrainingCourseAssignment.module_responses).where(TrainingCourseAssignment.tenant_id == tenant_id)
    )
    question_totals: dict[str, list[float]] = {}
    for (module_responses,) in result.all():
        for _module_id, answers in (module_responses or {}).items():
            for q_key, option_key in answers.items():
                if option_key not in _SENTIMENT_VALUE:
                    continue
                question_totals.setdefault(q_key, []).append(_SENTIMENT_VALUE[option_key])
    if not question_totals:
        return None
    question_averages = [sum(vals) / len(vals) for vals in question_totals.values()]
    return sum(question_averages) / len(question_averages)


def _new_access_token() -> str:
    return secrets.token_urlsafe(32)


# ── Course CRUD ──────────────────────────────────────────────────────────

async def create_course(db: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID, title: str, description: str | None, category: str, modules: list[dict]) -> TrainingCourse:
    course = TrainingCourse(
        id=uuid.uuid4(), tenant_id=tenant_id, title=title, description=description,
        category=category, created_by_user_id=user_id,
    )
    db.add(course)
    await db.flush()
    for i, m in enumerate(modules):
        db.add(TrainingCourseModule(
            id=uuid.uuid4(), tenant_id=tenant_id, course_id=course.id, order_index=i,
            format=m["format"], title=m["title"], content=m.get("content"), duration_minutes=m.get("duration_minutes"),
        ))
    await db.commit()
    result = await db.execute(select(TrainingCourse).where(TrainingCourse.id == course.id).options(selectinload(TrainingCourse.modules)))
    return result.scalar_one()


async def add_module(db: AsyncSession, course: TrainingCourse, format: str, title: str, content: str | None, duration_minutes: int | None) -> TrainingCourseModule:
    existing = await db.execute(select(TrainingCourseModule.order_index).where(TrainingCourseModule.course_id == course.id))
    next_index = max([i for i in existing.scalars().all()], default=-1) + 1
    module = TrainingCourseModule(
        id=uuid.uuid4(), tenant_id=course.tenant_id, course_id=course.id, order_index=next_index,
        format=format, title=title, content=content, duration_minutes=duration_minutes,
    )
    db.add(module)
    await db.commit()
    await db.refresh(module)
    return module


async def reorder_modules(db: AsyncSession, course: TrainingCourse, ordered_module_ids: list[uuid.UUID]) -> None:
    result = await db.execute(select(TrainingCourseModule).where(TrainingCourseModule.course_id == course.id))
    modules_by_id = {m.id: m for m in result.scalars().all()}
    for i, module_id in enumerate(ordered_module_ids):
        if module_id in modules_by_id:
            modules_by_id[module_id].order_index = i
    await db.commit()


# ── Assignment ───────────────────────────────────────────────────────────

async def _get_or_create_assignment(
    db: AsyncSession, tenant_id: uuid.UUID, course_id: uuid.UUID, recipient_hash: str, source: str,
    campaign_id: uuid.UUID | None = None,
) -> tuple[TrainingCourseAssignment, bool]:
    """Get-or-create on the (tenant, course, recipient) unique constraint —
    same convention as phishing_service._ensure_training_assignment, so a
    repeat trigger (another failure, or re-running a standalone assign)
    never produces a duplicate. Returns (assignment, was_newly_created)."""
    result = await db.execute(
        select(TrainingCourseAssignment).where(
            TrainingCourseAssignment.tenant_id == tenant_id,
            TrainingCourseAssignment.course_id == course_id,
            TrainingCourseAssignment.recipient_hash == recipient_hash,
        )
    )
    assignment = result.scalar_one_or_none()
    if assignment is not None:
        return assignment, False
    assignment = TrainingCourseAssignment(
        id=uuid.uuid4(), tenant_id=tenant_id, course_id=course_id, recipient_hash=recipient_hash,
        access_token=_new_access_token(), source=source, campaign_id=campaign_id, status="assigned",
    )
    db.add(assignment)
    await db.commit()
    await db.refresh(assignment)
    return assignment, True


def _tracking_base_url() -> str:
    from app.config import settings
    return settings.command_phishing_track_base_url.rstrip("/")


async def _send_course_assignment_email(db: AsyncSession, tenant: Tenant, course: TrainingCourse, assignment: TrainingCourseAssignment, email: str) -> None:
    url = f"{_tracking_base_url()}/phishing-training/{assignment.access_token}"
    await send_email(
        db, to=email,
        subject=f"Security training assigned: {course.title}",
        title="A short security training has been assigned to you",
        body_html=(
            f"<p>Your organization has assigned you a short security training course: <strong>{course.title}</strong>.</p>"
            f"<p><a href=\"{url}\">Start the course</a></p>"
            f"<p style=\"color:#888;font-size:12px;\">This is part of an authorized security awareness program run via Sentinel Command.</p>"
        ),
        text_body=f"Your organization has assigned you a security training course: {course.title}. Start it here: {url}",
    )


async def assign_course_to_target_list(
    db: AsyncSession, tenant: Tenant, course: TrainingCourse, target_list: PhishingTargetList,
    audience_type: str, department: str | None,
) -> tuple[int, int]:
    """Standalone assignment path, independent of any phishing campaign —
    mirrors the launch route's own department-audience filtering exactly.
    Returns (newly_assigned, already_assigned)."""
    entries = target_list.entries or []
    if audience_type == "department" and department:
        entries = [e for e in entries if e.get("department") == department]

    newly_assigned = 0
    already_assigned = 0
    for entry in entries:
        email = entry.get("email")
        if not email:
            continue
        recipient_hash = _hash_recipient(email, tenant.id)
        assignment, created = await _get_or_create_assignment(db, tenant.id, course.id, recipient_hash, "standalone")
        if created:
            newly_assigned += 1
            await _send_course_assignment_email(db, tenant, course, assignment, email)
        else:
            already_assigned += 1
    return newly_assigned, already_assigned


async def assign_course_on_phishing_failure(
    db: AsyncSession, tenant: Tenant, campaign: PhishingCampaign, target_list: PhishingTargetList, recipient_hash: str,
) -> TrainingCourseAssignment | None:
    """Called instead of the single micro-lesson (phishing_service.
    _ensure_training_assignment) when tenant.auto_assign_training_course_id
    is set. Needs the real email once, purely to send the assignment
    notification — resolved the same way unmask_recipient() does (re-hash
    the target list's current entries), but never logged as an unmask:
    this is the system doing what launch_campaign() already implicitly
    does with the same data to send the original simulated email, not an
    admin bypassing privacy."""
    course = await db.get(TrainingCourse, tenant.auto_assign_training_course_id)
    if not course or course.tenant_id != tenant.id:
        return None

    assignment, created = await _get_or_create_assignment(
        db, tenant.id, course.id, recipient_hash, "phishing_failure", campaign_id=campaign.id,
    )
    if created:
        for entry in target_list.entries or []:
            email = entry.get("email")
            if email and _hash_recipient(email, tenant.id) == recipient_hash:
                await _send_course_assignment_email(db, tenant, course, assignment, email)
                break
    return assignment


# ── Recipient-facing pages (unauthenticated, token-gated) ──────────────────

def _page_shell(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title></head>
<body style="font-family:sans-serif;max-width:560px;margin:60px auto;padding:0 20px;background:#f4f5f7;color:#1a1c22;">
  <div style="background:#fff;border-radius:12px;padding:28px 32px;box-shadow:0 1px 3px rgba(0,0,0,.08);">{body}</div>
</body></html>"""


_UNKNOWN_TOKEN_HTML = _page_shell("Security training", "<h2>This link has expired</h2><p>This training link is no longer active.</p>")


async def _find_assignment(db: AsyncSession, token: str) -> TrainingCourseAssignment | None:
    result = await db.execute(select(TrainingCourseAssignment).where(TrainingCourseAssignment.access_token == token))
    return result.scalar_one_or_none()


async def render_course_home_page(db: AsyncSession, token: str) -> str | None:
    assignment = await _find_assignment(db, token)
    if not assignment:
        return None
    course_result = await db.execute(
        select(TrainingCourse).where(TrainingCourse.id == assignment.course_id).options(selectinload(TrainingCourse.modules))
    )
    course = course_result.scalar_one_or_none()
    if not course:
        return None

    rows = []
    for m in course.modules:
        done = str(m.id) in assignment.completed_module_ids
        mark = "&#x2713; Done" if done else f"{m.duration_minutes or 2} min"
        rows.append(
            f'<a href="/phishing-training/{token}/module/{m.id}" '
            f'style="display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid #eee;'
            f'text-decoration:none;color:#1a1c22;">'
            f'<span>{m.title}</span><span style="color:{"#2a5b52" if done else "#888"};font-size:12px;">{mark}</span></a>'
        )
    complete_note = (
        '<p style="margin-top:18px;color:#2a5b52;font-weight:600;">You\'ve completed this course. Thanks.</p>'
        if assignment.status == "completed" else
        '<p style="margin-top:18px;color:#666;font-size:13px;">Work through each module below — it only takes a few minutes.</p>'
    )
    body = f"""
      <div style="display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;color:#2a5b52;background:#e0efe5;padding:3px 10px;border-radius:999px;margin-bottom:14px;">SECURITY TRAINING</div>
      <h2 style="margin:0 0 6px;">{course.title}</h2>
      <p style="color:#666;font-size:13px;margin:0 0 18px;">{course.description or ''}</p>
      {''.join(rows)}
      {complete_note}
    """
    return _page_shell(course.title, body)


def _render_article_module(module: TrainingCourseModule, token: str, done: bool, preview: bool = False) -> str:
    action = "" if (done or preview) else f"""
      <form method="POST" action="/phishing-training/{token}/module/{module.id}/complete" style="margin-top:20px;">
        <button type="submit" style="padding:9px 18px;background:#2a5b52;color:#fff;border:none;border-radius:6px;font-size:13px;cursor:pointer;">Mark as read</button>
      </form>"""
    back_link = "" if preview else f'<p style="margin-top:20px;"><a href="/phishing-training/{token}" style="color:#2a5b52;font-size:13px;">&larr; Back to course</a></p>'
    return f"""
      <h2 style="margin:0 0 14px;">{module.title}</h2>
      <div style="line-height:1.6;color:#333;">{module.content or ''}</div>
      {action}
      {back_link}
    """


def _render_video_module(module: TrainingCourseModule, token: str, done: bool, preview: bool = False) -> str:
    action = "" if (done or preview) else f"""
      <form method="POST" action="/phishing-training/{token}/module/{module.id}/complete" style="margin-top:20px;">
        <button type="submit" style="padding:9px 18px;background:#2a5b52;color:#fff;border:none;border-radius:6px;font-size:13px;cursor:pointer;">I've watched this</button>
      </form>"""
    back_link = "" if preview else f'<p style="margin-top:20px;"><a href="/phishing-training/{token}" style="color:#2a5b52;font-size:13px;">&larr; Back to course</a></p>'
    return f"""
      <h2 style="margin:0 0 14px;">{module.title}</h2>
      <p style="font-size:13px;"><a href="{module.content}" target="_blank" rel="noopener">Watch the video &rarr;</a></p>
      {action}
      {back_link}
    """


def _render_survey_module(module: TrainingCourseModule, token: str, done: bool, preview: bool = False) -> str:
    if done:
        return f"""
          <h2 style="margin:0 0 14px;">{module.title}</h2>
          <p style="color:#2a5b52;">Thanks — your response has been recorded.</p>
          <p style="margin-top:20px;"><a href="/phishing-training/{token}" style="color:#2a5b52;font-size:13px;">&larr; Back to course</a></p>
        """
    questions_html = ""
    for q in SURVEY_QUESTIONS:
        options_html = "".join(
            f'<label style="display:block;margin:4px 0;font-size:13px;cursor:pointer;">'
            f'<input type="radio" name="{q["key"]}" value="{opt_key}" required{" disabled" if preview else ""}> {opt_label}</label>'
            for opt_key, opt_label in _SURVEY_OPTIONS
        )
        questions_html += f'<div style="margin:16px 0;"><p style="font-size:13px;font-weight:600;margin:0 0 6px;">{q["label"]}</p>{options_html}</div>'
    if preview:
        # Real question text/options so an admin can verify actual
        # wording, disabled inputs (nothing to interact with), no <form>
        # or submit button — there's no real assignment to submit to in a
        # preview, and no back-link — redundant with the preview surface's
        # own sidebar/close chrome around this content.
        return f"""
          <h2 style="margin:0 0 6px;">{module.title}</h2>
          <p style="color:#666;font-size:12.5px;">Your answers are never shown against your name — only combined with everyone else's.</p>
          {questions_html}
        """
    return f"""
      <h2 style="margin:0 0 6px;">{module.title}</h2>
      <p style="color:#666;font-size:12.5px;">Your answers are never shown against your name — only combined with everyone else's.</p>
      <form method="POST" action="/phishing-training/{token}/module/{module.id}/complete">
        {questions_html}
        <button type="submit" style="margin-top:12px;padding:9px 18px;background:#2a5b52;color:#fff;border:none;border-radius:6px;font-size:13px;cursor:pointer;">Submit</button>
      </form>
      <p style="margin-top:20px;"><a href="/phishing-training/{token}" style="color:#2a5b52;font-size:13px;">&larr; Back to course</a></p>
    """


async def render_module_page(db: AsyncSession, token: str, module_id: str) -> str | None:
    assignment = await _find_assignment(db, token)
    if not assignment:
        return None
    try:
        module = await db.get(TrainingCourseModule, uuid.UUID(module_id))
    except ValueError:
        return None
    if not module or module.course_id != assignment.course_id:
        return None

    done = str(module.id) in assignment.completed_module_ids
    if module.format == "video_embed":
        return _page_shell(module.title, _render_video_module(module, token, done))
    if module.format == "survey":
        return _page_shell(module.title, _render_survey_module(module, token, done))
    return _page_shell(module.title, _render_article_module(module, token, done))


# ── Admin preview (authenticated, Phishing Simulation roadmap Phase 34)
# — same visual language as the real recipient pages above, reused
# directly rather than rebuilt, so a preview is pixel-identical to what a
# real recipient actually sees. Takes an already-loaded, already-
# tenant-verified course/module directly (no db/token lookup of its own
# — that's the caller's job, training_course.py's own _get_owned_course),
# and never shows a "done" state since nothing is ever completed in a
# preview. ───────────────────────────────────────────────────────────────

def render_course_preview_home_page(course: TrainingCourse) -> str:
    """Module rows are plain text, not <a href> — this HTML is injected
    into an iframe's srcdoc with no authenticated navigation available to
    it, so all preview navigation is owned by the caller's own sidebar
    UI, entirely outside this markup."""
    rows = []
    for m in course.modules:
        rows.append(
            f'<div style="display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid #eee;">'
            f'<span>{m.title}</span><span style="color:#888;font-size:12px;">{m.duration_minutes or 2} min</span></div>'
        )
    body = f"""
      <div style="display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;color:#8a6d1a;background:#fbecc7;padding:3px 10px;border-radius:999px;margin-bottom:8px;">PREVIEW — nothing here is tracked</div>
      <div style="display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;color:#2a5b52;background:#e0efe5;padding:3px 10px;border-radius:999px;margin-bottom:14px;margin-left:6px;">SECURITY TRAINING</div>
      <h2 style="margin:0 0 6px;">{course.title}</h2>
      <p style="color:#666;font-size:13px;margin:0 0 18px;">{course.description or ''}</p>
      {''.join(rows)}
    """
    return _page_shell(course.title, body)


def render_module_preview_page(module: TrainingCourseModule) -> str:
    """token is passed as "" — safe because preview=True guarantees
    neither _render_*_module function ever reads it (both only
    interpolate token into the form action / back-link, both suppressed
    in preview mode)."""
    if module.format == "video_embed":
        return _page_shell(module.title, _render_video_module(module, "", False, preview=True))
    if module.format == "survey":
        return _page_shell(module.title, _render_survey_module(module, "", False, preview=True))
    return _page_shell(module.title, _render_article_module(module, "", False, preview=True))


async def complete_module(db: AsyncSession, token: str, module_id: str, survey_answers: dict[str, str] | None = None) -> str | None:
    assignment = await _find_assignment(db, token)
    if not assignment:
        return None
    try:
        module_uuid = uuid.UUID(module_id)
    except ValueError:
        return None
    module = await db.get(TrainingCourseModule, module_uuid)
    if not module or module.course_id != assignment.course_id:
        return None

    if module_id not in assignment.completed_module_ids:
        assignment.completed_module_ids = [*assignment.completed_module_ids, module_id]
    if module.format == "survey" and survey_answers:
        assignment.module_responses = {**assignment.module_responses, module_id: survey_answers}

    all_module_ids_result = await db.execute(select(TrainingCourseModule.id).where(TrainingCourseModule.course_id == assignment.course_id))
    total_module_ids = {str(mid) for mid in all_module_ids_result.scalars().all()}
    if total_module_ids and total_module_ids.issubset(set(assignment.completed_module_ids)):
        assignment.status = "completed"
        assignment.completed_at = datetime.now(timezone.utc)

    await db.commit()
    return await render_course_home_page(db, token)


# ── Reminders (Phishing Simulation roadmap Phase 24 — nothing like this
# existed anywhere in the codebase before this) ─────────────────────────────

async def send_training_reminders() -> None:
    from app.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        await _send_training_reminders(db)


async def _send_training_reminders(db: AsyncSession) -> int:
    """Re-emails anyone with an incomplete assignment past their tenant's
    configured interval, capped at training_reminder_max_count (0 disables
    reminders entirely for that tenant). Sent count matches
    training_reminder_max_count real cycles, never indefinite nagging."""
    result = await db.execute(
        select(TrainingCourseAssignment).where(TrainingCourseAssignment.status == "assigned")
    )
    sent = 0
    for assignment in result.scalars().all():
        tenant = await db.get(Tenant, assignment.tenant_id)
        if not tenant or assignment.reminder_count >= tenant.training_reminder_max_count:
            continue
        last = assignment.last_reminder_sent_at or assignment.assigned_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - last < timedelta(days=tenant.training_reminder_interval_days):
            continue

        course = await db.get(TrainingCourse, assignment.course_id)
        if not course:
            continue
        email = None
        if assignment.source == "phishing_failure" and assignment.campaign_id:
            campaign = await db.get(PhishingCampaign, assignment.campaign_id)
            target_list = await db.get(PhishingTargetList, campaign.target_list_id) if campaign else None
        else:
            # Standalone assignments aren't tied to one campaign's target
            # list — re-hash against every target list this tenant has,
            # same technique, just without a single obvious list to start from.
            target_list = None
            lists_result = await db.execute(select(PhishingTargetList).where(PhishingTargetList.tenant_id == tenant.id))
            for tl in lists_result.scalars().all():
                for entry in tl.entries or []:
                    if entry.get("email") and _hash_recipient(entry["email"], tenant.id) == assignment.recipient_hash:
                        target_list = tl
                        break
                if target_list:
                    break
        if target_list:
            for entry in target_list.entries or []:
                if entry.get("email") and _hash_recipient(entry["email"], tenant.id) == assignment.recipient_hash:
                    email = entry["email"]
                    break
        if not email:
            continue

        await _send_course_assignment_email(db, tenant, course, assignment, email)
        assignment.reminder_count += 1
        assignment.last_reminder_sent_at = datetime.now(timezone.utc)
        await db.commit()
        sent += 1
    return sent
