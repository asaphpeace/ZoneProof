import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, event, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AuditLogEntry(Base):
    """
    Append-only record of security/admin-relevant actions for a tenant.
    Written explicitly at the call sites that matter (auth, billing, domain
    lifecycle, MSP client management) rather than via a generic middleware
    hook — see audit_service.py for the rationale.
    """
    __tablename__ = "audit_log_entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)

    # Null when the action was performed by a background job, not a user
    # (e.g. the recommendation engine's scheduled evaluation never logs here —
    # it writes Alert rows — but a future system action could).
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)  # denormalized — survives user deletion

    action: Mapped[str] = mapped_column(String(100), index=True)  # e.g. "domain.deleted", "team.role_changed"
    target_type: Mapped[str | None] = mapped_column(String(50), nullable=True)  # e.g. "domain", "user", "invite"
    target_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    target_label: Mapped[str | None] = mapped_column(String(300), nullable=True)  # human-readable, e.g. domain name

    before: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    after: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship()  # type: ignore[name-defined]

    __table_args__ = (
        Index("ix_audit_log_tenant_created", "tenant_id", "created_at"),
    )


# Real, database-level immutability. UPDATE is rejected UNLESS it's exactly
# the one legitimate system mutation this table allows: actor_user_id being
# nulled by the users.id FK's ON DELETE SET NULL when the acting user is
# later removed (actor_email is denormalized specifically to survive that —
# see the class docstring above). Every other column must be unchanged for
# that to pass; anything else is rejected. DELETE is rejected unless the
# transaction opted in via the `sentinel.allow_audit_log_delete` GUC (set
# only by delete_account()'s tenant-erasure path in app/routers/auth.py,
# whose cascade is the one legitimate way rows here are ever removed).
# Kept identical, deliberately, to
# alembic/versions/5195e95231d0_audit_log_immutability_trigger.py — that
# migration is what applies this to a real dev/prod DB via `alembic
# upgrade head`; this event listener is what applies the same trigger when
# a DB is instead built via Base.metadata.create_all (tests/conftest.py,
# and entrypoint.sh's create-then-stamp path for a brand-new database).
_CREATE_IMMUTABILITY_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION prevent_audit_log_tampering() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.actor_user_id IS NULL
           AND NEW.tenant_id = OLD.tenant_id
           AND NEW.actor_email IS NOT DISTINCT FROM OLD.actor_email
           AND NEW.action = OLD.action
           AND NEW.target_type IS NOT DISTINCT FROM OLD.target_type
           AND NEW.target_id IS NOT DISTINCT FROM OLD.target_id
           AND NEW.target_label IS NOT DISTINCT FROM OLD.target_label
           AND NEW.before IS NOT DISTINCT FROM OLD.before
           AND NEW.after IS NOT DISTINCT FROM OLD.after
           AND NEW.ip_address IS NOT DISTINCT FROM OLD.ip_address
           AND NEW.created_at = OLD.created_at
        THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'audit_log_entries is immutable: UPDATE is not permitted';
    ELSIF TG_OP = 'DELETE' THEN
        IF current_setting('sentinel.allow_audit_log_delete', true) IS DISTINCT FROM 'on' THEN
            RAISE EXCEPTION 'audit_log_entries is immutable: DELETE is not permitted outside an authorized tenant-erasure transaction';
        END IF;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
"""

_DROP_IMMUTABILITY_TRIGGER_SQL = "DROP TRIGGER IF EXISTS audit_log_entries_immutable ON audit_log_entries"

_CREATE_IMMUTABILITY_TRIGGER_SQL = """
CREATE TRIGGER audit_log_entries_immutable
BEFORE UPDATE OR DELETE ON audit_log_entries
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_tampering();
"""

# asyncpg's prepared-statement protocol ("Parse" step of the extended query
# protocol, used by Connection.execute(DDL(...))) rejects a CREATE FUNCTION
# body that itself contains semicolons with "cannot insert multiple
# commands into a prepared statement" — even a single well-formed
# dollar-quoted function. exec_driver_sql bypasses that path (the same way
# alembic's op.execute() does, which is why the migration version of this
# SQL works unmodified), so call it directly from a plain event listener
# instead of handing SQLAlchemy a DDL() construct.
def _create_audit_log_immutability_trigger(target, connection, **kw) -> None:
    if connection.dialect.name != "postgresql":
        return
    # CREATE OR REPLACE handles the function; a trigger has no such clause
    # (portably, across Postgres versions this codebase might run against),
    # so drop-then-create — idempotent either way against a DB this ran on
    # before (e.g. tests/conftest.py's drop_all doesn't know about a
    # trigger it never created, only tables it owns via Base.metadata).
    connection.exec_driver_sql(_CREATE_IMMUTABILITY_FUNCTION_SQL)
    connection.exec_driver_sql(_DROP_IMMUTABILITY_TRIGGER_SQL)
    connection.exec_driver_sql(_CREATE_IMMUTABILITY_TRIGGER_SQL)


event.listen(AuditLogEntry.__table__, "after_create", _create_audit_log_immutability_trigger)
