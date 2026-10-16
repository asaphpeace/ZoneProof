"""add brand scan runs

Revision ID: e5b1f3a7c2d9
Revises: c9a4e7b2d1f8
Create Date: 2026-09-30 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'e5b1f3a7c2d9'
down_revision: Union[str, None] = 'c9a4e7b2d1f8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'brand_scan_runs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('profile_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_profiles.id', ondelete='CASCADE'), nullable=False),
        sa.Column('status', sa.String(12), nullable=False, server_default='queued'),
        sa.Column('phase', sa.String(20), nullable=True),
        sa.Column('progress_done', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('progress_total', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('triggered_by', sa.String(12), nullable=False, server_default='manual'),
        sa.Column('result', postgresql.JSONB(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_brand_scan_runs_tenant_id', 'brand_scan_runs', ['tenant_id'])
    op.create_index('ix_brand_scan_runs_profile_id', 'brand_scan_runs', ['profile_id'])
    op.create_index(
        'uq_brand_scan_runs_one_active', 'brand_scan_runs', ['profile_id'], unique=True,
        postgresql_where=sa.text("status IN ('queued','running')"),
    )


def downgrade() -> None:
    op.drop_table('brand_scan_runs')
