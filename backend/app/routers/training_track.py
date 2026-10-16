"""
Unauthenticated training-course access — same discipline as
phishing_track.py: no auth (the recipient never has a Sentinel account),
an opaque unguessable access_token in the path, and an unrecognized token
answered identically to a recognized one (silently), so this can't be
probed to distinguish a real assignment from a guess. Plain HTML forms,
no JS dependency, since this is reached via a link in an email opened in
whatever browser the recipient has.
"""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.training_course_service import (
    SURVEY_QUESTIONS, _UNKNOWN_TOKEN_HTML, complete_module, render_course_home_page, render_module_page,
)

router = APIRouter(prefix="/phishing-training", tags=["training-tracking"])


@router.get("/{token}", response_class=HTMLResponse)
async def track_course_home(token: str, db: AsyncSession = Depends(get_db)):
    html = await render_course_home_page(db, token)
    return HTMLResponse(content=html or _UNKNOWN_TOKEN_HTML)


@router.get("/{token}/module/{module_id}", response_class=HTMLResponse)
async def track_module(token: str, module_id: str, db: AsyncSession = Depends(get_db)):
    html = await render_module_page(db, token, module_id)
    return HTMLResponse(content=html or _UNKNOWN_TOKEN_HTML)


@router.post("/{token}/module/{module_id}/complete", response_class=HTMLResponse)
async def complete_module_route(token: str, module_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    form = await request.form()
    # A survey POST carries one field per SURVEY_QUESTIONS key; an
    # article/video "mark as read" POST carries none — same handler
    # either way, complete_module() only uses survey_answers when the
    # module's own format is 'survey'.
    survey_answers = {q["key"]: form[q["key"]] for q in SURVEY_QUESTIONS if q["key"] in form}
    html = await complete_module(db, token, module_id, survey_answers or None)
    return HTMLResponse(content=html or _UNKNOWN_TOKEN_HTML)
