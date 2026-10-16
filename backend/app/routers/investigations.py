from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Actor, Investigation, InvestigationEvent
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.finding import AttackTechniqueOut
from app.schemas.investigation import ActorOut, InvestigationDetailOut, InvestigationEventOut, InvestigationOut
from app.services.attack_technique_mapping import attack_techniques_for_actions

router = APIRouter(prefix="/investigations", tags=["investigations"])


async def _get_investigation(investigation_id: str, db: AsyncSession, user: User) -> Investigation:
    result = await db.execute(
        select(Investigation).where(
            Investigation.id == investigation_id,
            Investigation.tenant_id == user.tenant_id,
        )
    )
    investigation = result.scalar_one_or_none()
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return investigation


def _actor_out(actor: Actor) -> ActorOut:
    return ActorOut(id=str(actor.id), display_name=actor.display_name, email=actor.email)


async def _to_out(investigation: Investigation, db: AsyncSession) -> InvestigationOut:
    actor = await db.get(Actor, investigation.actor_id)
    count_result = await db.execute(
        select(InvestigationEvent).where(InvestigationEvent.investigation_id == investigation.id)
    )
    event_count = len(count_result.scalars().all())
    return InvestigationOut(
        id=str(investigation.id), actor=_actor_out(actor), status=investigation.status,
        opened_at=investigation.opened_at.isoformat(), last_activity_at=investigation.last_activity_at.isoformat(),
        dismissed_at=investigation.dismissed_at.isoformat() if investigation.dismissed_at else None,
        event_count=event_count,
    )


@router.get("", response_model=list[InvestigationOut])
async def list_investigations(
    include_dismissed: bool = False,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = select(Investigation).where(Investigation.tenant_id == user.tenant_id)
    if not include_dismissed:
        query = query.where(Investigation.dismissed_at.is_(None))
    result = await db.execute(query.order_by(Investigation.last_activity_at.desc()))
    return [await _to_out(i, db) for i in result.scalars().all()]


@router.get("/{investigation_id}", response_model=InvestigationDetailOut)
async def get_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    investigation = await _get_investigation(investigation_id, db, user)
    summary = await _to_out(investigation, db)

    result = await db.execute(
        select(InvestigationEvent)
        .where(InvestigationEvent.investigation_id == investigation.id)
        .order_by(InvestigationEvent.occurred_at.asc())
    )
    events = [
        InvestigationEventOut(
            id=str(e.id), source=e.source, event_id=e.event_id, action_or_event_type=e.action_or_event_type,
            occurred_at=e.occurred_at.isoformat(), raw_detail=e.raw_detail,
            attack_techniques=[
                AttackTechniqueOut(**t) for t in attack_techniques_for_actions([e.action_or_event_type])
            ],
        )
        for e in result.scalars().all()
    ]
    return InvestigationDetailOut(**summary.model_dump(), events=events)


@router.post("/{investigation_id}/dismiss", response_model=InvestigationOut)
async def dismiss_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    investigation = await _get_investigation(investigation_id, db, user)
    if investigation.dismissed_at:
        raise HTTPException(status_code=400, detail="Investigation is already dismissed")
    investigation.dismissed_at = datetime.now(timezone.utc)
    investigation.dismissed_by_user_id = user.id
    await db.commit()
    return await _to_out(investigation, db)
