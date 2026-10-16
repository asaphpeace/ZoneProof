"""reference captures of the customer's own page, and probe jobs that are not tied to a candidate

Revision ID: d4f8b2c6e0a1
Revises: c3e7a1b5d9f4
Create Date: 2026-10-09 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'd4f8b2c6e0a1'
down_revision: Union[str, None] = 'c3e7a1b5d9f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column('brand_probe_jobs', 'candidate_id', existing_type=postgresql.UUID(as_uuid=True), nullable=True)
    op.add_column('brand_probe_jobs', sa.Column('profile_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_profiles.id', ondelete='CASCADE'), nullable=True))
    op.create_index('ix_brand_probe_jobs_profile_id', 'brand_probe_jobs', ['profile_id'])
    op.create_table(
        'brand_reference_captures',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('profile_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_profiles.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('captured_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('screenshot_enc', sa.Text(), nullable=True),
        sa.Column('screenshot_mime', sa.String(12), nullable=True),
        sa.Column('layout_hash', sa.String(64), nullable=True),
        sa.Column('palette', sa.String(24), nullable=True),
    )
    op.create_index('ix_brand_reference_captures_tenant_id', 'brand_reference_captures', ['tenant_id'])


def downgrade() -> None:
    op.drop_index('ix_brand_reference_captures_tenant_id', table_name='brand_reference_captures')
    op.drop_table('brand_reference_captures')
    op.drop_index('ix_brand_probe_jobs_profile_id', table_name='brand_probe_jobs')
    op.drop_column('brand_probe_jobs', 'profile_id')
    op.execute("DELETE FROM brand_probe_jobs WHERE candidate_id IS NULL")
    op.alter_column('brand_probe_jobs', 'candidate_id', existing_type=postgresql.UUID(as_uuid=True), nullable=False)
