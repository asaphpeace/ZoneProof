"""
Unauthenticated tracking endpoints — the URLs embedded in a phishing
simulation email. No auth by design (the recipient never has a Sentinel
account); the opaque, unguessable recipient_token in the path is what
prevents one recipient's link from being usable to spoof another's events
(PHISHING_DESIGN.md Section 3.2). An unrecognized token is answered
identically to a recognized one (silently, without an error), so that
probing this endpoint can't be used to distinguish a valid campaign
recipient from an invalid guess.
"""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.phishing_service import (
    record_click, record_credential_submit, record_lesson_response, record_open, record_report,
    render_lesson_page,
)

router = APIRouter(prefix="/phishing-track", tags=["phishing-tracking"])

# 1x1 transparent GIF — the smallest valid image byte sequence for an open-tracking pixel.
_PIXEL_GIF = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b"
)


@router.get("/{token}/pixel.gif")
async def track_open(token: str, request: Request, db: AsyncSession = Depends(get_db)):
    await record_open(db, token, request.client.host if request.client else None, request.headers.get("user-agent"))
    return Response(content=_PIXEL_GIF, media_type="image/gif")


@router.get("/{token}/click", response_class=HTMLResponse)
async def track_click(token: str, request: Request, db: AsyncSession = Depends(get_db)):
    html = await record_click(db, token, request.client.host if request.client else None, request.headers.get("user-agent"))
    return HTMLResponse(content=html)


@router.post("/{token}/submit", response_class=HTMLResponse)
async def track_submit(token: str, request: Request, db: AsyncSession = Depends(get_db)):
    # Deliberately never reads request.form() — the submitted credentials
    # themselves must never reach this process, let alone get logged or
    # stored, per PHISHING_DESIGN.md's carryover of the "never persists a
    # password" rule.
    html = await record_credential_submit(
        db, token, request.client.host if request.client else None, request.headers.get("user-agent"),
    )
    return HTMLResponse(content=html)


@router.get("/{token}/report", response_class=HTMLResponse)
async def track_report(token: str, request: Request, db: AsyncSession = Depends(get_db)):
    html = await record_report(db, token, request.client.host if request.client else None, request.headers.get("user-agent"))
    return HTMLResponse(content=html)


# Same silent-unknown-token convention as every route above — an
# unrecognized token still gets a plausible 200 page, never a 404 that
# would confirm or deny whether it was ever valid.
_UNKNOWN_TOKEN_LESSON_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security awareness</title></head>
<body style="font-family:sans-serif;max-width:480px;margin:80px auto;">
  <h2>This link has expired</h2>
  <p>This security-awareness link is no longer active.</p>
</body></html>"""


@router.get("/{token}/lesson", response_class=HTMLResponse)
async def track_lesson(token: str, db: AsyncSession = Depends(get_db)):
    html = await render_lesson_page(db, token)
    return HTMLResponse(content=html or _UNKNOWN_TOKEN_LESSON_HTML)


@router.post("/{token}/lesson/respond", response_class=HTMLResponse)
async def track_lesson_respond(
    token: str, reflection_response: str = Form(...), db: AsyncSession = Depends(get_db),
):
    # Form(...), not a JSON body — the lesson page is a plain HTML <form>,
    # same reasoning as every other tracking endpoint: it must work in an
    # email client's embedded browser with no JS dependency.
    html = await record_lesson_response(db, token, reflection_response)
    return HTMLResponse(content=html or _UNKNOWN_TOKEN_LESSON_HTML)
