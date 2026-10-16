from pydantic import BaseModel


class TrainingCourseModuleCreate(BaseModel):
    format: str  # article | video_embed | survey
    title: str
    content: str | None = None  # HTML for article, embed URL for video_embed, ignored for survey
    duration_minutes: int | None = None


class TrainingCourseModuleOut(BaseModel):
    id: str
    order_index: int
    format: str
    title: str
    content: str | None
    duration_minutes: int | None


class TrainingCourseCreate(BaseModel):
    title: str
    description: str | None = None
    category: str = "General"
    modules: list[TrainingCourseModuleCreate] = []


class TrainingCourseUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    category: str | None = None


class TrainingCourseOut(BaseModel):
    id: str
    title: str
    description: str | None
    category: str
    modules: list[TrainingCourseModuleOut]
    created_at: str
    updated_at: str


class TrainingCourseAssignRequest(BaseModel):
    target_list_id: str
    # Mirrors LaunchCampaignRequest's audience scoping exactly — "everyone"
    # (default) assigns the whole list, "department" requires department.
    # No "individual" mode here (unlike campaign launch): assigning a
    # course to a hand-picked few recipients isn't a real use case this
    # phase scopes for — a course targets a real audience, not a retry.
    audience_type: str = "everyone"
    department: str | None = None


class TrainingCourseAssignResultOut(BaseModel):
    newly_assigned: int
    already_assigned: int


class TrainingCourseAssignmentOut(BaseModel):
    id: str
    recipient_hash: str
    status: str
    source: str
    modules_completed: int
    modules_total: int
    assigned_at: str
    completed_at: str | None
    reminder_count: int


class SurveyQuestionAggregateOut(BaseModel):
    question_key: str
    question_label: str
    # option_key -> count, across every real submitted response tenant-wide.
    # Never a per-person breakdown — see training_course.py's model docstring.
    counts: dict[str, int]
    response_count: int
