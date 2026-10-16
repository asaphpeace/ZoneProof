"""add brand reporting-service submissions

Revision ID: f9b3d7e1a5c8
Revises: e8a2c6d0f4b7
Create Date: 2026-10-06 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'f9b3d7e1a5c8'
down_revision: Union[str, None] = 'e8a2c6d0f4b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'brand_submissions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('candidate_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_candidates.id', ondelete='CASCADE'), nullable=False),
        sa.Column('service', sa.String(24), nullable=False),
        sa.Column('status', sa.String(12), nullable=False, server_default='submitted'),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('created_by_user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('candidate_id', 'service', name='uq_brand_submissions_candidate_service'),
    )
    op.create_index('ix_brand_submissions_tenant_id', 'brand_submissions', ['tenant_id'])
    op.create_index('ix_brand_submissions_candidate_id', 'brand_submissions', ['candidate_id'])


def downgrade() -> None:
    op.drop_index('ix_brand_submissions_candidate_id', table_name='brand_submissions')
    op.drop_index('ix_brand_submissions_tenant_id', table_name='brand_submissions')
    op.drop_table('brand_submissions')
