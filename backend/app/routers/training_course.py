import csv
import io
import uuid as _uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.phishing import PhishingTargetList
from app.models.training_course import TrainingCourse, TrainingCourseAssignment, TrainingCourseModule
from app.models.user import Tenant, User
from app.routers.auth import _require_admin_or_approver, get_current_user
from app.schemas.training_course import (
    SurveyQuestionAggregateOut, TrainingCourseAssignmentOut, TrainingCourseAssignRequest,
    TrainingCourseAssignResultOut, TrainingCourseCreate, TrainingCourseModuleCreate, TrainingCourseModuleOut,
    TrainingCourseOut, TrainingCourseUpdate,
)
from app.services import audit_service
from app.services.training_course_service import (
    SURVEY_QUESTIONS, add_module, assign_course_to_target_list, create_course,
    render_course_preview_home_page, render_module_preview_page, reorder_modules,
)

router = APIRouter(tags=["training-courses"])


def _module_out(m: TrainingCourseModule) -> TrainingCourseModuleOut:
    return TrainingCourseModuleOut(
        id=str(m.id), order_index=m.order_index, format=m.format, title=m.title,
        content=m.content, duration_minutes=m.duration_minutes,
    )


def _course_out(c: TrainingCourse) -> TrainingCourseOut:
    return TrainingCourseOut(
        id=str(c.id), title=c.title, description=c.description, category=c.category,
        modules=[_module_out(m) for m in c.modules],
        created_at=c.created_at.isoformat(), updated_at=c.updated_at.isoformat(),
    )


async def _get_owned_course(db: AsyncSession, user: User, course_id: str) -> TrainingCourse:
    try:
        cid = _uuid.UUID(course_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Course not found")
    result = await db.execute(
        select(TrainingCourse).where(TrainingCourse.id == cid, TrainingCourse.tenant_id == user.tenant_id)
        .options(selectinload(TrainingCourse.modules))
    )
    course = result.scalar_one_or_none()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    return course


@router.get("/training-courses", response_model=list[TrainingCourseOut])
async def list_courses(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    result = await db.execute(
        select(TrainingCourse).where(TrainingCourse.tenant_id == user.tenant_id).order_by(TrainingCourse.updated_at.desc())
        .options(selectinload(TrainingCourse.modules))
    )
    return [_course_out(c) for c in result.scalars().all()]


@router.post("/training-courses", response_model=TrainingCourseOut, status_code=201)
async def create_course_route(
    payload: TrainingCourseCreate, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    _require_admin_or_approver(user)
    for m in payload.modules:
        if m.format not in ("article", "video_embed", "survey"):
            raise HTTPException(status_code=400, detail=f"Unknown module format '{m.format}'")
    course = await create_course(
        db, user.tenant_id, user.id, payload.title, payload.description, payload.category,
        [m.model_dump() for m in payload.modules],
    )
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="training.course_created",
        target_type="training_course", target_id=str(course.id), target_label=course.title,
    )
    await db.commit()
    return _course_out(course)


@router.get("/training-courses/{course_id}", response_model=TrainingCourseOut)
async def get_course(course_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    course = await _get_owned_course(db, user, course_id)
    return _course_out(course)


@router.get("/training-courses/{course_id}/preview", response_class=HTMLResponse)
async def preview_course_home(course_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    course = await _get_owned_course(db, user, course_id)
    return HTMLResponse(content=render_course_preview_home_page(course))


@router.get("/training-courses/{course_id}/preview/module/{module_id}", response_class=HTMLResponse)
async def preview_course_module(course_id: str, module_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    course = await _get_owned_course(db, user, course_id)
    module = next((m for m in course.modules if str(m.id) == module_id), None)
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")
    return HTMLResponse(content=render_module_preview_page(module))


@router.patch("/training-courses/{course_id}", response_model=TrainingCourseOut)
async def update_course_route(
    course_id: str, payload: TrainingCourseUpdate, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    _require_admin_or_approver(user)
    course = await _get_owned_course(db, user, course_id)
    if payload.title is not None:
        course.title = payload.title
    if payload.description is not None:
        course.description = payload.description
    if payload.category is not None:
        course.category = payload.category
    await db.commit()
    await db.refresh(course)
    return _course_out(course)


@router.delete("/training-courses/{course_id}", status_code=204)
async def delete_course(course_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    _require_admin_or_approver(user)
    course = await _get_owned_course(db, user, course_id)
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="training.course_deleted",
        target_type="training_course", target_id=str(course.id), target_label=course.title,
    )
    await db.delete(course)
    await db.commit()


@router.post("/training-courses/{course_id}/modules", response_model=TrainingCourseModuleOut, status_code=201)
async def add_module_route(
    course_id: str, payload: TrainingCourseModuleCreate, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    _require_admin_or_approver(user)
    if payload.format not in ("article", "video_embed", "survey"):
        raise HTTPException(status_code=400, detail=f"Unknown module format '{payload.format}'")
    course = await _get_owned_course(db, user, course_id)
    module = await add_module(db, course, payload.format, payload.title, payload.content, payload.duration_minutes)
    return _module_out(module)


@router.delete("/training-course-modules/{module_id}", status_code=204)
async def delete_module_route(module_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    _require_admin_or_approver(user)
    try:
        mid = _uuid.UUID(module_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Module not found")
    module = await db.get(TrainingCourseModule, mid)
    if not module or module.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Module not found")
    await db.delete(module)
    await db.commit()


@router.put("/training-courses/{course_id}/modules/order", response_model=TrainingCourseOut)
async def reorder_modules_route(
    course_id: str, module_ids: list[str], db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    _require_admin_or_approver(user)
    course = await _get_owned_course(db, user, course_id)
    try:
        ordered = [_uuid.UUID(mid) for mid in module_ids]
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid module id in order list")
    await reorder_modules(db, course, ordered)
    # populate_existing=True is load-bearing here: `course` is already in
    # this session's identity map with its `modules` collection loaded
    # from the _get_owned_course() call above, and a plain re-SELECT does
    # NOT overwrite an already-populated relationship collection by
    # default — it would silently keep returning the pre-reorder list.
    result = await db.execute(
        select(TrainingCourse).where(TrainingCourse.id == course.id)
        .options(selectinload(TrainingCourse.modules)).execution_options(populate_existing=True)
    )
    return _course_out(result.scalar_one())


@router.post("/training-courses/{course_id}/assign", response_model=TrainingCourseAssignResultOut)
async def assign_course_route(
    course_id: str, payload: TrainingCourseAssignRequest, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    _require_admin_or_approver(user)
    course = await _get_owned_course(db, user, course_id)
    result = await db.execute(
        select(PhishingTargetList).where(PhishingTargetList.id == payload.target_list_id, PhishingTargetList.tenant_id == user.tenant_id)
    )
    target_list = result.scalar_one_or_none()
    if not target_list:
        raise HTTPException(status_code=400, detail="target_list_id does not resolve to a target list")
    if payload.audience_type == "department" and not payload.department:
        raise HTTPException(status_code=400, detail="audience_type='department' requires a department")

    tenant = await db.get(Tenant, user.tenant_id)
    newly_assigned, already_assigned = await assign_course_to_target_list(
        db, tenant, course, target_list, payload.audience_type, payload.department,
    )
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="training.course_assigned",
        target_type="training_course", target_id=str(course.id), target_label=course.title,
        after={"target_list": target_list.name, "audience": payload.audience_type, "newly_assigned": newly_assigned},
    )
    await db.commit()
    return TrainingCourseAssignResultOut(newly_assigned=newly_assigned, already_assigned=already_assigned)


def _assignment_out(a: TrainingCourseAssignment, modules_total: int) -> TrainingCourseAssignmentOut:
    return TrainingCourseAssignmentOut(
        id=str(a.id), recipient_hash=a.recipient_hash, status=a.status, source=a.source,
        modules_completed=len(a.completed_module_ids), modules_total=modules_total,
        assigned_at=a.assigned_at.isoformat(), completed_at=a.completed_at.isoformat() if a.completed_at else None,
        reminder_count=a.reminder_count,
    )


@router.get("/training-courses/{course_id}/assignments", response_model=list[TrainingCourseAssignmentOut])
async def list_course_assignments(course_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    course = await _get_owned_course(db, user, course_id)
    result = await db.execute(
        select(TrainingCourseAssignment).where(TrainingCourseAssignment.course_id == course.id).order_by(TrainingCourseAssignment.assigned_at.desc())
    )
    modules_total = len(course.modules)
    return [_assignment_out(a, modules_total) for a in result.scalars().all()]


@router.get("/training-courses/{course_id}/assignments/export.csv")
async def export_course_assignments(course_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    course = await _get_owned_course(db, user, course_id)
    result = await db.execute(
        select(TrainingCourseAssignment).where(TrainingCourseAssignment.course_id == course.id).order_by(TrainingCourseAssignment.assigned_at.desc())
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["recipient_hash", "status", "source", "modules_completed", "modules_total", "assigned_at", "completed_at", "reminder_count"])
    modules_total = len(course.modules)
    for a in result.scalars().all():
        writer.writerow([
            a.recipient_hash, a.status, a.source, len(a.completed_module_ids), modules_total,
            a.assigned_at.isoformat(), a.completed_at.isoformat() if a.completed_at else "", a.reminder_count,
        ])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=training-{course.id}.csv"},
    )


@router.get("/training-survey-results", response_model=list[SurveyQuestionAggregateOut])
async def get_survey_results(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Tenant-wide aggregate across every survey-module response this
    tenant has ever collected — never a per-recipient breakdown, since no
    unmask path exists for training_course_assignments at all (see the
    model's own docstring). Real counts only; a question nobody's
    answered yet just doesn't appear, rather than showing a fabricated 0."""
    result = await db.execute(
        select(TrainingCourseAssignment.module_responses).where(TrainingCourseAssignment.tenant_id == user.tenant_id)
    )
    counts: dict[str, dict[str, int]] = {q["key"]: {} for q in SURVEY_QUESTIONS}
    response_counts: dict[str, int] = {q["key"]: 0 for q in SURVEY_QUESTIONS}
    for (module_responses,) in result.all():
        for _module_id, answers in (module_responses or {}).items():
            for q_key, option_key in answers.items():
                if q_key not in counts:
                    continue
                counts[q_key][option_key] = counts[q_key].get(option_key, 0) + 1
                response_counts[q_key] += 1

    labels = {q["key"]: q["label"] for q in SURVEY_QUESTIONS}
    return [
        SurveyQuestionAggregateOut(question_key=k, question_label=labels[k], counts=v, response_count=response_counts[k])
        for k, v in counts.items() if response_counts[k] > 0
    ]
