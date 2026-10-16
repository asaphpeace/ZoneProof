"""add brand guard tables

Revision ID: c9a4e7b2d1f8
Revises: b8f2d6c4e9a1
Create Date: 2026-09-30 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'c9a4e7b2d1f8'
down_revision: Union[str, None] = 'b8f2d6c4e9a1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'brand_profiles',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('domain_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('domains.id', ondelete='CASCADE'), nullable=False),
        sa.Column('brand_name', sa.String(120), nullable=False),
        sa.Column('keywords', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('official_domains', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('login_urls', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('last_scanned_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_ct_poll_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_scan_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('tenant_id', 'domain_id', name='uq_brand_profiles_tenant_domain'),
    )
    op.create_index('ix_brand_profiles_tenant_id', 'brand_profiles', ['tenant_id'])
    op.create_index('ix_brand_profiles_domain_id', 'brand_profiles', ['domain_id'])

    op.create_table(
        'brand_candidates',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('profile_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_profiles.id', ondelete='CASCADE'), nullable=False),
        sa.Column('candidate_domain', sa.String(253), nullable=False),
        sa.Column('status', sa.String(20), nullable=False, server_default='new'),
        sa.Column('identity_score', sa.Float(), nullable=False, server_default='0'),
        sa.Column('abuse_score', sa.Float(), nullable=False, server_default='0'),
        sa.Column('impact', sa.String(10), nullable=False, server_default='low'),
        sa.Column('urgency', sa.String(10), nullable=False, server_default='low'),
        sa.Column('threat_class', sa.String(30), nullable=True),
        sa.Column('sources', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('enrichment', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('last_assessed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reviewed_by_user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('analyst_note', sa.Text(), nullable=True),
        sa.Column('alerted_at', sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint('profile_id', 'candidate_domain', name='uq_brand_candidates_profile_domain'),
    )
    op.create_index('ix_brand_candidates_tenant_id', 'brand_candidates', ['tenant_id'])
    op.create_index('ix_brand_candidates_profile_id', 'brand_candidates', ['profile_id'])
    op.create_index('ix_brand_candidates_tenant_status', 'brand_candidates', ['tenant_id', 'status'])

    op.create_table(
        'candidate_evidence',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('candidate_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_candidates.id', ondelete='CASCADE'), nullable=False),
        sa.Column('signal', sa.String(40), nullable=False),
        sa.Column('dimension', sa.String(10), nullable=False),
        sa.Column('weight', sa.Float(), nullable=False, server_default='0'),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('data', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('observed_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_candidate_evidence_candidate_id', 'candidate_evidence', ['candidate_id'])


def downgrade() -> None:
    op.drop_table('candidate_evidence')
    op.drop_table('brand_candidates')
    op.drop_table('brand_profiles')
