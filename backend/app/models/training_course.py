"""
Training course library (Phishing Simulation roadmap Phase 24) — the
multi-module assignable content this product never had before: everything
prior to this was one auto-triggered post-click micro-lesson
(TrainingAssignment in phishing.py), which stays exactly as-is. A course
is a real, separate concept: assignable independent of any phishing
failure, made of ordered modules (article / video_embed / survey),
completable module-by-module.

Deliberately no video-hosting/file-upload infrastructure — 'video_embed'
modules hold an externally-hosted URL (Loom/YouTube/etc.), not an
uploaded file. Building real storage infra is a separate investment from
shipping a real, usable course library.

Every assignment is pseudonymized the same way PhishingEvent already is —
recipient_hash only, an unguessable access_token as the sole means of
unauthenticated access (mirroring PhishingEvent.recipient_token). Unlike
phishing events, there is deliberately no admin-unmask path for a course
assignment at all in this phase — a stronger anonymity bar than
'pseudonymous until admin unmask', chosen specifically for the survey
module type ('never attributable to a named individual' per the roadmap),
and kept uniform across every assignment rather than only for surveys.
"""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class TrainingCourse(Base):
    __tablename__ = "training_courses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)

    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    category: Mapped[str] = mapped_column(String(100), default="General")
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    modules: Mapped[list["TrainingCourseModule"]] = relationship(
        back_populates="course", order_by="TrainingCourseModule.order_index", cascade="all, delete-orphan",
    )


class TrainingCourseModule(Base):
    __tablename__ = "training_course_modules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    course_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("training_courses.id", ondelete="CASCADE"), index=True)

    order_index: Mapped[int] = mapped_column(Integer, default=0)
    format: Mapped[str] = mapped_column(String(20))  # article | video_embed | survey
    title: Mapped[str] = mapped_column(String(200))
    # HTML body for 'article', an external embed URL for 'video_embed',
    # unused for 'survey' — a survey's questions are fixed in code
    # (training_course_service.SURVEY_QUESTIONS), never admin-authored
    # free text, matching the roadmap's "fixed questions, not open-ended"
    # scope for the culture-survey feature.
    content: Mapped[str | None] = mapped_column(String(20000), nullable=True)
    duration_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    course: Mapped["TrainingCourse"] = relationship(back_populates="modules")


class TrainingCourseAssignment(Base):
    __tablename__ = "training_course_assignments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "course_id", "recipient_hash", name="uq_course_assignment_recipient"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    course_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("training_courses.id", ondelete="CASCADE"), index=True)

    recipient_hash: Mapped[str] = mapped_column(String(64))
    access_token: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    source: Mapped[str] = mapped_column(String(20))  # phishing_failure | standalone
    # Set only for source='phishing_failure' — SET NULL (not CASCADE) so
    # the assignment record survives even if the campaign row it
    # originated from is ever removed; the assignment stands on its own.
    campaign_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("phishing_campaigns.id", ondelete="SET NULL"), nullable=True)

    status: Mapped[str] = mapped_column(String(20), default="assigned")  # assigned | completed
    completed_module_ids: Mapped[list] = mapped_column(JSONB, default=list)
    # Survey answers, keyed by module_id: {"<module_id>": {"q1": "agree", ...}}.
    # Never resolved back to an identity anywhere in this codebase — see
    # module docstring on why no unmask path exists for this table.
    module_responses: Mapped[dict] = mapped_column(JSONB, default=dict)

    reminder_count: Mapped[int] = mapped_column(Integer, default=0)
    last_reminder_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
