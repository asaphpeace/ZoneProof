"""email telemetry integrations: connections and feeds (V2 plan D1)

Revision ID: b3d8f1a6c2e9
Revises: a7c1e4b9d2f6
Create Date: 2026-10-16 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'b3d8f1a6c2e9'
down_revision: Union[str, None] = 'a7c1e4b9d2f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'integration_connections',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('vendor', sa.String(40), nullable=False),
        sa.Column('label', sa.String(120), nullable=False),
        sa.Column('encrypted_credentials', sa.Text(), nullable=False),
        sa.Column('status', sa.String(16), nullable=False, server_default='untested'),
        sa.Column('last_error_kind', sa.String(24), nullable=True),
        sa.Column('last_tested_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_integration_connections_tenant_id', 'integration_connections', ['tenant_id'])
    op.create_table(
        'integration_feeds',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('integration_connections.id', ondelete='CASCADE'), nullable=False),
        sa.Column('feed_key', sa.String(40), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('interval_seconds', sa.Integer(), nullable=False, server_default='3600'),
        sa.Column('last_started', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_finished', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_ok', sa.Boolean(), nullable=True),
        sa.Column('last_error_kind', sa.String(24), nullable=True),
        sa.Column('last_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_duration_s', sa.Float(), nullable=True),
        sa.Column('cursor', sa.String(200), nullable=True),
        sa.UniqueConstraint('connection_id', 'feed_key', name='uq_integration_feed'),
    )
    op.create_index('ix_integration_feeds_connection_id', 'integration_feeds', ['connection_id'])


def downgrade() -> None:
    op.drop_index('ix_integration_feeds_connection_id', table_name='integration_feeds')
    op.drop_table('integration_feeds')
    op.drop_index('ix_integration_connections_tenant_id', table_name='integration_connections')
    op.drop_table('integration_connections')
