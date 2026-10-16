"""
Email-telemetry integrations (V2 plan D1): a tenant's connection to an outside
vendor, and the feeds pulled through it.

Credentials are stored encrypted (crypto_service) as one JSON blob and are never
returned by any endpoint, not even masked per value. Error state is only ever the
fixed kind from job_registry.KINDS, never exception text.
"""
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class IntegrationConnection(Base):
    __tablename__ = "integration_connections"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    vendor: Mapped[str] = mapped_column(String(40))
    label: Mapped[str] = mapped_column(String(120))
    encrypted_credentials: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="untested")  # untested | ok | failing
    last_error_kind: Mapped[str | None] = mapped_column(String(24), nullable=True)
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    feeds: Mapped[list["IntegrationFeed"]] = relationship(
        back_populates="connection", cascade="all, delete-orphan", lazy="selectin"
    )


class IntegrationFeed(Base):
    __tablename__ = "integration_feeds"
    __table_args__ = (UniqueConstraint("connection_id", "feed_key", name="uq_integration_feed"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("integration_connections.id", ondelete="CASCADE"), index=True
    )
    feed_key: Mapped[str] = mapped_column(String(40))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    last_started: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_finished: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_error_kind: Mapped[str | None] = mapped_column(String(24), nullable=True)
    last_count: Mapped[int] = mapped_column(Integer, default=0)
    last_duration_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    # High-water mark the adapter hands back so the next pull continues where this one stopped.
    cursor: Mapped[str | None] = mapped_column(String(200), nullable=True)

    connection: Mapped[IntegrationConnection] = relationship(back_populates="feeds")
