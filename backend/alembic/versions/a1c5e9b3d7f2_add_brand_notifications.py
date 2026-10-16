"""add brand notification channels and delivery log

Revision ID: a1c5e9b3d7f2
Revises: f9b3d7e1a5c8
Create Date: 2026-10-06 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'a1c5e9b3d7f2'
down_revision: Union[str, None] = 'f9b3d7e1a5c8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'brand_notify_channels',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('kind', sa.String(8), nullable=False),
        sa.Column('label', sa.String(80), nullable=False),
        sa.Column('target_enc', sa.Text(), nullable=False),
        sa.Column('secret_enc', sa.Text(), nullable=True),
        sa.Column('min_severity', sa.String(8), nullable=False, server_default='warn'),
        sa.Column('digest', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('last_digest_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_status', sa.String(8), nullable=True),
        sa.Column('last_error', sa.String(300), nullable=True),
        sa.Column('last_sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by_user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_brand_notify_channels_tenant_id', 'brand_notify_channels', ['tenant_id'])
    op.create_table(
        'brand_notify_log',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('channel_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_notify_channels.id', ondelete='CASCADE'), nullable=False),
        sa.Column('alert_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('alerts.id', ondelete='CASCADE'), nullable=True),
        sa.Column('kind', sa.String(8), nullable=False),
        sa.Column('status', sa.String(8), nullable=False),
        sa.Column('error', sa.String(300), nullable=True),
        sa.Column('sent_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('channel_id', 'alert_id', name='uq_brand_notify_log_channel_alert'),
    )
    op.create_index('ix_brand_notify_log_tenant_id', 'brand_notify_log', ['tenant_id'])
    op.create_index('ix_brand_notify_log_channel_id', 'brand_notify_log', ['channel_id'])


def downgrade() -> None:
    op.drop_index('ix_brand_notify_log_channel_id', table_name='brand_notify_log')
    op.drop_index('ix_brand_notify_log_tenant_id', table_name='brand_notify_log')
    op.drop_table('brand_notify_log')
    op.drop_index('ix_brand_notify_channels_tenant_id', table_name='brand_notify_channels')
    op.drop_table('brand_notify_channels')
