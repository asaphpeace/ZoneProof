"""add brand campaigns and campaign membership on candidates

Revision ID: f1b4d6a8c3e2
Revises: e9a2c6d4b8f1
Create Date: 2026-10-02 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'f1b4d6a8c3e2'
down_revision: Union[str, None] = 'e9a2c6d4b8f1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'brand_campaigns',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('profile_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_profiles.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(160), nullable=False),
        sa.Column('verdict', sa.String(24), nullable=False, server_default='not_enough'),
        sa.Column('facts', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('member_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_brand_campaigns_tenant_id', 'brand_campaigns', ['tenant_id'])
    op.create_index('ix_brand_campaigns_profile_id', 'brand_campaigns', ['profile_id'])
    op.add_column('brand_candidates', sa.Column('campaign_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_campaigns.id', ondelete='SET NULL'), nullable=True))
    op.add_column('brand_candidates', sa.Column('campaign_locked', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.create_index('ix_brand_candidates_campaign_id', 'brand_candidates', ['campaign_id'])


def downgrade() -> None:
    op.drop_index('ix_brand_candidates_campaign_id', table_name='brand_candidates')
    op.drop_column('brand_candidates', 'campaign_locked')
    op.drop_column('brand_candidates', 'campaign_id')
    op.drop_index('ix_brand_campaigns_profile_id', table_name='brand_campaigns')
    op.drop_index('ix_brand_campaigns_tenant_id', table_name='brand_campaigns')
    op.drop_table('brand_campaigns')
