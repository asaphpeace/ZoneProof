"""
POST /prospect-assessment — a real, passive, consent-free domain posture
check backing the sales team's "Prospect Assessment" tool. See
prospect_assessment_service.py's module docstring for what this replaced
and why. Authenticated (existing Command user only, not public — this
makes real outbound DNS/HTTPS calls against arbitrary domains) and
rate-limited at Exposure scan's same strict tier, for the same reason:
"3/minute — the strictest, since it makes real outbound network calls."
"""
from fastapi import APIRouter, Depends, HTTPException, Request

from app.models.user import User
from app.rate_limit import limiter
from app.routers.auth import get_current_user
from app.schemas.prospect import ProspectAssessmentOut, ProspectAssessmentRequest
from app.services.prospect_assessment_service import assess_domain

router = APIRouter(prefix="/prospect-assessment", tags=["prospect"])


@router.post("", response_model=ProspectAssessmentOut)
@limiter.limit("3/minute")
async def run_prospect_assessment(
    request: Request,
    payload: ProspectAssessmentRequest,
    user: User = Depends(get_current_user),
):
    domain = payload.domain.strip().lower()
    if not domain or "." not in domain or " " in domain:
        raise HTTPException(status_code=400, detail="Enter a valid domain, e.g. example.com")
    return await assess_domain(domain)
