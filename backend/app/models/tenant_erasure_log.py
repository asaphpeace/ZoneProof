import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class TenantErasureLog(Base):
    """
    Durable, tenant-independent record that a workspace was permanently
    erased — created in the same transaction as the erasing DELETE, before
    it executes. Deliberately NOT a foreign key to tenants.id: the whole
    point is that this row outlives the tenant it describes (which cascades
    away, taking audit_log_entries with it — see delete_account()'s comment
    in app/routers/auth.py). tenant_id here is a plain denormalized value,
    not a live reference.
    """
    __tablename__ = "tenant_erasure_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    tenant_name: Mapped[str] = mapped_column(String(200))
    deleted_by_email: Mapped[str] = mapped_column(String(320))
    domain_count: Mapped[int] = mapped_column(Integer)
    user_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
