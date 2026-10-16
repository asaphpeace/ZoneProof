"""
Last known state of each background job, kept across restarts and shared by instances.

One row per job key. The instance that runs the job (the leader, see C1) writes
it after every run; the Data sources page reads it so a restart or a standby
instance still shows the real history. Counters are cumulative and incremented
in the database, so they survive a restart rather than resetting to zero.

Failure detail is only ever the fixed kind from job_registry.KINDS.
"""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class JobRun(Base):
    __tablename__ = "job_runs"

    job_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    runs: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_started: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_finished: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_failure_kind: Mapped[str | None] = mapped_column(String(24), nullable=True)
    last_duration_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
