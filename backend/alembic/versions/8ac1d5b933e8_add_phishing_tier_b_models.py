"""add phishing tier b models

Revision ID: 8ac1d5b933e8
Revises: 351249525fc3
Create Date: 2026-07-19 08:30:41.083994

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '8ac1d5b933e8'
down_revision: Union[str, None] = '351249525fc3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('phishing_target_lists',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('entries', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_phishing_target_lists_tenant_id'), 'phishing_target_lists', ['tenant_id'], unique=False)
    op.create_table('phishing_campaigns',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('engagement_id', sa.UUID(), nullable=False),
    sa.Column('target_list_id', sa.UUID(), nullable=False),
    sa.Column('template_id', sa.String(length=50), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('launched_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['engagement_id'], ['engagements.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['target_list_id'], ['phishing_target_lists.id'], ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_phishing_campaigns_engagement_id'), 'phishing_campaigns', ['engagement_id'], unique=False)
    op.create_index(op.f('ix_phishing_campaigns_tenant_id'), 'phishing_campaigns', ['tenant_id'], unique=False)
    op.create_table('phishing_events',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('campaign_id', sa.UUID(), nullable=False),
    sa.Column('recipient_hash', sa.String(length=64), nullable=False),
    sa.Column('recipient_token', sa.String(length=43), nullable=False),
    sa.Column('event_type', sa.String(length=20), nullable=False),
    sa.Column('occurred_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['campaign_id'], ['phishing_campaigns.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_phishing_events_campaign_id'), 'phishing_events', ['campaign_id'], unique=False)
    op.create_index('ix_phishing_events_recipient_token', 'phishing_events', ['recipient_token'], unique=False)
    op.create_index(op.f('ix_phishing_events_tenant_id'), 'phishing_events', ['tenant_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_phishing_events_tenant_id'), table_name='phishing_events')
    op.drop_index('ix_phishing_events_recipient_token', table_name='phishing_events')
    op.drop_index(op.f('ix_phishing_events_campaign_id'), table_name='phishing_events')
    op.drop_table('phishing_events')
    op.drop_index(op.f('ix_phishing_campaigns_tenant_id'), table_name='phishing_campaigns')
    op.drop_index(op.f('ix_phishing_campaigns_engagement_id'), table_name='phishing_campaigns')
    op.drop_table('phishing_campaigns')
    op.drop_index(op.f('ix_phishing_target_lists_tenant_id'), table_name='phishing_target_lists')
    op.drop_table('phishing_target_lists')
