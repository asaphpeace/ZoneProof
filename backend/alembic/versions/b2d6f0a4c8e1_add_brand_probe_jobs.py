"""add brand probe jobs for the egress worker

Revision ID: b2d6f0a4c8e1
Revises: a1c5e9b3d7f2
Create Date: 2026-10-07 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'b2d6f0a4c8e1'
down_revision: Union[str, None] = 'a1c5e9b3d7f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'brand_probe_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('candidate_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_candidates.id', ondelete='CASCADE'), nullable=False),
        sa.Column('host', sa.String(253), nullable=False),
        sa.Column('kind', sa.String(8), nullable=False, server_default='light'),
        sa.Column('status', sa.String(10), nullable=False, server_default='queued'),
        sa.Column('claimed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('result', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('error', sa.String(200), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_brand_probe_jobs_tenant_id', 'brand_probe_jobs', ['tenant_id'])
    op.create_index('ix_brand_probe_jobs_candidate_id', 'brand_probe_jobs', ['candidate_id'])
    op.create_index('ix_brand_probe_jobs_status_created', 'brand_probe_jobs', ['status', 'created_at'])


def downgrade() -> None:
    op.drop_index('ix_brand_probe_jobs_status_created', table_name='brand_probe_jobs')
    op.drop_index('ix_brand_probe_jobs_candidate_id', table_name='brand_probe_jobs')
    op.drop_index('ix_brand_probe_jobs_tenant_id', table_name='brand_probe_jobs')
    op.drop_table('brand_probe_jobs')
