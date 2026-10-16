from pydantic import BaseModel


class ProspectAssessmentRequest(BaseModel):
    domain: str


class ProspectCheckOut(BaseModel):
    label: str
    found: bool
    detail: str


class ProspectAssessmentOut(BaseModel):
    domain: str
    score: float
    grade: str
    grade_color: str
    checks: list[ProspectCheckOut]
    not_assessed: list[str]
