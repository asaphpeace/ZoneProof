"""add actor identity resolution and investigation models

Continuous Threat Detection & Response (ITDR_DESIGN.md) — Actor/
ActorIdentity give a resolved human identity spanning multiple systems
(the fix for the design's original flaw of keying on a raw per-source
principal string); Investigation/InvestigationEvent are the per-actor
evidence trail, deliberately with no FK to a specific connection so they
survive a connection being revoked or removed. cloud_account_connections
gains its own last_threat_poll_at/threat_detection_status/
threat_detection_error, separate from the existing scan-status fields,
since continuous polling is a materially different pipeline with its own
failure modes from the periodic deep scan. server_default backfills
existing rows as 'never_run'. Autogenerate again flagged the same
unrelated pre-existing drift on dmarc_reports/tls_reports/users/
service_accounts seen in every migration this session — excluded, still
out of scope.

Revision ID: 1a1aa3632727
Revises: 6cf7f82d9991
Create Date: 2026-07-15
"""
from alembic import op
import sqlalchemy as sa

revision = '1a1aa3632727'
down_revision = '6cf7f82d9991'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('actors',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('display_name', sa.String(length=200), nullable=True),
    sa.Column('email', sa.String(length=320), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_actors_email'), 'actors', ['email'], unique=False)
    op.create_index(op.f('ix_actors_tenant_id'), 'actors', ['tenant_id'], unique=False)

    op.create_table('actor_identities',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('actor_id', sa.UUID(), nullable=False),
    sa.Column('source', sa.String(length=20), nullable=False),
    sa.Column('principal_id', sa.String(length=2048), nullable=False),
    sa.Column('resolved_via', sa.String(length=20), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['actor_id'], ['actors.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'source', 'principal_id', name='uq_actor_identity_source_principal')
    )
    op.create_index(op.f('ix_actor_identities_actor_id'), 'actor_identities', ['actor_id'], unique=False)
    op.create_index(op.f('ix_actor_identities_tenant_id'), 'actor_identities', ['tenant_id'], unique=False)

    op.create_table('investigations',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('actor_id', sa.UUID(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('opened_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_activity_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('dismissed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('dismissed_by_user_id', sa.UUID(), nullable=True),
    sa.ForeignKeyConstraint(['actor_id'], ['actors.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['dismissed_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_investigations_actor_id'), 'investigations', ['actor_id'], unique=False)
    op.create_index(op.f('ix_investigations_tenant_id'), 'investigations', ['tenant_id'], unique=False)

    op.create_table('investigation_events',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('investigation_id', sa.UUID(), nullable=False),
    sa.Column('source', sa.String(length=20), nullable=False),
    sa.Column('event_id', sa.String(length=200), nullable=False),
    sa.Column('action_or_event_type', sa.String(length=200), nullable=False),
    sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('raw_detail', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'source', 'event_id', name='uq_investigation_event_source_event_id')
    )
    op.create_index(op.f('ix_investigation_events_investigation_id'), 'investigation_events', ['investigation_id'], unique=False)
    op.create_index(op.f('ix_investigation_events_tenant_id'), 'investigation_events', ['tenant_id'], unique=False)

    op.add_column('cloud_account_connections', sa.Column('last_threat_poll_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('cloud_account_connections', sa.Column('threat_detection_status', sa.String(length=20), nullable=False, server_default='never_run'))
    op.add_column('cloud_account_connections', sa.Column('threat_detection_error', sa.String(length=1000), nullable=True))


def downgrade() -> None:
    op.drop_column('cloud_account_connections', 'threat_detection_error')
    op.drop_column('cloud_account_connections', 'threat_detection_status')
    op.drop_column('cloud_account_connections', 'last_threat_poll_at')

    op.drop_index(op.f('ix_investigation_events_tenant_id'), table_name='investigation_events')
    op.drop_index(op.f('ix_investigation_events_investigation_id'), table_name='investigation_events')
    op.drop_table('investigation_events')

    op.drop_index(op.f('ix_investigations_tenant_id'), table_name='investigations')
    op.drop_index(op.f('ix_investigations_actor_id'), table_name='investigations')
    op.drop_table('investigations')

    op.drop_index(op.f('ix_actor_identities_tenant_id'), table_name='actor_identities')
    op.drop_index(op.f('ix_actor_identities_actor_id'), table_name='actor_identities')
    op.drop_table('actor_identities')

    op.drop_index(op.f('ix_actors_tenant_id'), table_name='actors')
    op.drop_index(op.f('ix_actors_email'), table_name='actors')
    op.drop_table('actors')
