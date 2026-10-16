"""audit log immutability trigger

Real, database-level guarantee that audit_log_entries cannot be tampered
with — today "immutable" only meant "no PATCH/DELETE route exists", which
is a property of the API surface, not the data. This adds a BEFORE
UPDATE/DELETE trigger that rejects the statement outright, so the
guarantee holds even against direct DB access (a compromised admin
session, a future route added without thinking, raw psql).

UPDATE is rejected UNLESS it's exactly the one legitimate system mutation
this table already documents: actor_user_id being nulled by the
`users.id` FK's ON DELETE SET NULL when the acting user is later removed
(AuditLogEntry.actor_email is explicitly denormalized to survive that —
see the model's docstring). The trigger checks every other column is
unchanged before allowing it; anything else — rewriting action/before/
after/target_* to hide what really happened — is rejected.

DELETE is rejected unless the current transaction has explicitly opted in
via the `sentinel.allow_audit_log_delete` session GUC. The one legitimate
case this exists for: deleting a Tenant cascades (ON DELETE CASCADE) to
that tenant's audit_log_entries rows, since an audit trail scoped to a
tenant that no longer exists can't be queried by anyone. delete_account()
in app/routers/auth.py sets this GUC with `SET LOCAL` (transaction-scoped,
auto-reset at commit/rollback) immediately before that delete — see the
comment there. Every other path, including a raw DELETE issued outside
that one sanctioned transaction, is rejected.

Revision ID: 5195e95231d0
Revises: 0a5be7b72874
Create Date: 2026-09-15

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '5195e95231d0'
down_revision: Union[str, None] = '0a5be7b72874'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE FUNCTION prevent_audit_log_tampering() RETURNS TRIGGER AS $$
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
    """)
    op.execute("""
        CREATE TRIGGER audit_log_entries_immutable
        BEFORE UPDATE OR DELETE ON audit_log_entries
        FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_tampering();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_entries_immutable ON audit_log_entries")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_log_tampering()")
