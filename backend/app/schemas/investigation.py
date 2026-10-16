from pydantic import BaseModel

from app.schemas.finding import AttackTechniqueOut


class InvestigationEventOut(BaseModel):
    id: str
    source: str
    event_id: str
    action_or_event_type: str
    occurred_at: str
    raw_detail: str | None
    attack_techniques: list[AttackTechniqueOut] = []


class ActorOut(BaseModel):
    id: str
    display_name: str | None
    email: str | None


class InvestigationOut(BaseModel):
    id: str
    actor: ActorOut
    status: str
    opened_at: str
    last_activity_at: str
    dismissed_at: str | None
    event_count: int


class InvestigationDetailOut(InvestigationOut):
    events: list[InvestigationEventOut]
