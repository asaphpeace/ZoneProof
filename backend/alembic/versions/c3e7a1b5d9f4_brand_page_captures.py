"""add encrypted page captures from the sandboxed renderer

Revision ID: c3e7a1b5d9f4
Revises: b2d6f0a4c8e1
Create Date: 2026-10-08 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'c3e7a1b5d9f4'
down_revision: Union[str, None] = 'b2d6f0a4c8e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'brand_page_captures',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('candidate_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_candidates.id', ondelete='CASCADE'), nullable=False),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('captured_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('retain_until', sa.DateTime(timezone=True), nullable=False),
        sa.Column('screenshot_enc', sa.Text(), nullable=True),
        sa.Column('screenshot_mime', sa.String(12), nullable=True),
        sa.Column('text_enc', sa.Text(), nullable=True),
        sa.Column('title', sa.String(200), nullable=True),
        sa.Column('final_url', sa.String(500), nullable=True),
        sa.Column('forms', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('nav_chain', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('stats', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.create_index('ix_brand_page_captures_tenant_id', 'brand_page_captures', ['tenant_id'])
    op.create_index('ix_brand_page_captures_candidate_id', 'brand_page_captures', ['candidate_id'])
    op.create_index('ix_brand_page_captures_retain_until', 'brand_page_captures', ['retain_until'])


def downgrade() -> None:
    op.drop_index('ix_brand_page_captures_retain_until', table_name='brand_page_captures')
    op.drop_index('ix_brand_page_captures_candidate_id', table_name='brand_page_captures')
    op.drop_index('ix_brand_page_captures_tenant_id', table_name='brand_page_captures')
    op.drop_table('brand_page_captures')
