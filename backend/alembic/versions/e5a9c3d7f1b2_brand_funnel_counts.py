"""add the Brand Guard funnel counters

Revision ID: e5a9c3d7f1b2
Revises: d4f8b2c6e0a1
Create Date: 2026-10-10 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'e5a9c3d7f1b2'
down_revision: Union[str, None] = 'd4f8b2c6e0a1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'brand_funnel_counts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('profile_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_profiles.id', ondelete='CASCADE'), nullable=False),
        sa.Column('day', sa.Date(), nullable=False),
        sa.Column('stage', sa.String(24), nullable=False),
        sa.Column('entered', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('passed', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('detail', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.UniqueConstraint('profile_id', 'day', 'stage', name='uq_brand_funnel_profile_day_stage'),
    )
    op.create_index('ix_brand_funnel_counts_tenant_id', 'brand_funnel_counts', ['tenant_id'])
    op.create_index('ix_brand_funnel_counts_profile_id', 'brand_funnel_counts', ['profile_id'])


def downgrade() -> None:
    op.drop_index('ix_brand_funnel_counts_profile_id', table_name='brand_funnel_counts')
    op.drop_index('ix_brand_funnel_counts_tenant_id', table_name='brand_funnel_counts')
    op.drop_table('brand_funnel_counts')
