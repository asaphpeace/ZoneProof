"""add brand takedown drafts and outcomes

Revision ID: e8a2c6d0f4b7
Revises: d7f1b5c9e3a6
Create Date: 2026-10-05 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'e8a2c6d0f4b7'
down_revision: Union[str, None] = 'd7f1b5c9e3a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'brand_takedowns',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('candidate_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_candidates.id', ondelete='CASCADE'), nullable=False),
        sa.Column('route_kind', sa.String(16), nullable=False),
        sa.Column('route_label', sa.String(200), nullable=False),
        sa.Column('how', sa.String(8), nullable=False),
        sa.Column('target', sa.String(320), nullable=False, server_default=''),
        sa.Column('certainty', sa.String(12), nullable=False),
        sa.Column('subject', sa.String(300), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('status', sa.String(14), nullable=False, server_default='draft'),
        sa.Column('evidence_hash', sa.String(64), nullable=True),
        sa.Column('created_by_user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('approved_by_user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('outcome_note', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_brand_takedowns_tenant_id', 'brand_takedowns', ['tenant_id'])
    op.create_index('ix_brand_takedowns_candidate_id', 'brand_takedowns', ['candidate_id'])


def downgrade() -> None:
    op.drop_index('ix_brand_takedowns_candidate_id', table_name='brand_takedowns')
    op.drop_index('ix_brand_takedowns_tenant_id', table_name='brand_takedowns')
    op.drop_table('brand_takedowns')
